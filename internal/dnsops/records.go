package dnsops

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/validators"
)

// DefaultRecordTTL is applied when a write does not carry a TTL and there is
// no existing RRSet TTL to inherit.
const DefaultRecordTTL = 3600

// CanonicalRecordType uppercases and trims a record type ("a" → "A"), the
// canonical form PowerDNS (and GoZone's own comparisons) expect.
func CanonicalRecordType(recordType string) string {
	return strings.ToUpper(strings.TrimSpace(recordType))
}

// NormalizeRecordName canonicalises a record name against its zone for the
// PowerDNS API: "@"" and "" resolve to the zone apex, a bare label ("www")
// is expanded against the zone, a name already ending with the zone suffix
// only gains the trailing dot, and the value is lowercased throughout.
// Without this normalisation PowerDNS silently returns an empty list for
// names that are syntactically valid but not canonical, and PATCHes create a
// second RRSet instead of updating the existing one.
func NormalizeRecordName(name, zoneName string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)
	zone := strings.ToLower(zoneName)
	if !strings.HasSuffix(zone, ".") {
		zone += "."
	}
	root := strings.TrimSuffix(zone, ".")
	if name == "@" || name == "" {
		return zone
	}
	// Already fully qualified (ends with dot)
	if strings.HasSuffix(name, ".") {
		if strings.EqualFold(name, zone) {
			return zone
		}
		return name
	}
	// Just the zone root (e.g., "example.com")
	if strings.EqualFold(name, root) {
		return zone
	}
	// Ends with zone suffix without trailing dot (e.g., "www.example.com")
	if strings.HasSuffix(name, "."+root) {
		return name + "."
	}
	// Bare name — append zone with dot (e.g., "www" -> "www.example.com.")
	return name + "." + zone
}

// asciiFold lowercases only ASCII A-Z. DNS case folding (RFC 4343) applies
// to ASCII letters alone: Go's strings.EqualFold and strings.ToLower apply
// Unicode mappings that would merge distinct names presented as raw UTF-8
// (the Kelvin sign U+212A folds to ASCII 'k' under Unicode, but the two are
// different DNS names on the wire).
func asciiFold(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}

// RRSetsMatch reports whether two RRSets are the same set, comparing name
// and type case-insensitively with DNS folding (ASCII only). DNS names are
// case-insensitive; case-preserving backends return original casing while
// submissions are lowercase; an exact match misses the RRSet and the REPLACE
// then drops its siblings.
func RRSetsMatch(aName, aType, bName, bType string) bool {
	return asciiFold(aName) == asciiFold(bName) && asciiFold(aType) == asciiFold(bType)
}

// RRSetKey returns the canonical map key for grouping RRSets across
// casings: the ASCII-folded name and type joined by "|".
func RRSetKey(name, rtype string) string {
	return asciiFold(name) + "|" + asciiFold(rtype)
}

// PriorityConflictError reports an MX/SRV submission whose content already
// embeds a leading priority that diverges from the explicitly provided
// Priority field value (wire data fed back in with a stale or zeroed
// priority). Silently re-embedding one of the two values would drop the
// other, so the write is rejected with an actionable message instead.
type PriorityConflictError struct {
	RecordType string
	Embedded   int
	Provided   int
}

// Error renders the conflict in a uniform, actionable form for every
// transport: "SRV content embeds priority 10 which conflicts with the
// priority field value 0; align them or remove the priority from the
// content".
func (e *PriorityConflictError) Error() string {
	return fmt.Sprintf("%s content embeds priority %d which conflicts with the priority field value %d; align them or remove the priority from the content",
		strings.ToUpper(e.RecordType), e.Embedded, e.Provided)
}

// PrepareRecordContent normalises record content for the PDNS PATCH API,
// returning the wire content and the value to store in RecordInfo.Priority.
// MX/SRV priority is embedded in the content (and the separate Priority
// element cleared, since PDNS rejects it); TXT/SPF content is quoted. When
// MX/SRV content already embeds a priority that conflicts with the provided
// one, it returns a *PriorityConflictError and zero values for content and
// priority. See the codec in internal/models for the per-type rules.
func PrepareRecordContent(recordType, content string, priority int) (string, int, error) {
	switch {
	case models.TypeHasPriority(recordType):
		// MX/SRV: wire data fed back in must agree with the provided
		// priority — never silently re-embed one of the two values.
		if embedded, ok := models.EmbeddedPriority(recordType, content); ok && embedded != priority {
			return "", 0, &PriorityConflictError{RecordType: recordType, Embedded: embedded, Provided: priority}
		}
		// Embed priority first, then ensure the FQDN target (the
		// last space-separated field) ends with a trailing dot.
		return models.EnsureTrailingDot(models.JoinPriority(recordType, priority, content)), 0, nil
	case models.TypeIsQuoted(recordType):
		return models.QuoteContent(recordType, content), priority, nil
	case models.TypeIsFQDNTarget(recordType):
		// CNAME/NS/PTR/ALIAS/DNAME/AFSDB/NAPTR: the entire content or the
		// last space-separated field is a DNS name target.
		return models.EnsureTrailingDot(content), priority, nil
	case models.TypeHasFQDNFields(recordType):
		// SOA/RP/MINFO/NSEC: specific fields are FQDNs but not in the last
		// position, so per-field normalisation is required.
		return models.EnsureTrailingDotFields(content, models.FQDNFieldIndices(recordType)), priority, nil
	case models.TypeHasQuotedFields(recordType):
		// CAA/HINFO/URI: specific fields are character-strings PowerDNS
		// requires quoted; already-quoted fields (possibly with spaces)
		// pass through untouched.
		return models.QuoteContentFields(content, models.QuotedFieldIndices(recordType)), priority, nil
	default:
		return content, priority, nil
	}
}

// DedupRecordsByContent removes records with identical wire content within
// an RRSet. DNS RRs in an RRSet are a set — duplicates are meaningless and
// PowerDNS rejects them. The first occurrence wins (preserving its Disabled
// flag and priority). Call this after PrepareRecordContent so that inputs
// canonicalising to the same content (e.g. a CNAME target with and without
// a trailing dot) collapse correctly; for MX/SRV the priority is embedded in
// the content, so targets with different priorities are kept.
func DedupRecordsByContent(records []models.RecordInfo) []models.RecordInfo {
	if len(records) < 2 {
		return records
	}
	seen := make(map[string]struct{}, len(records))
	out := make([]models.RecordInfo, 0, len(records))
	for _, r := range records {
		if _, ok := seen[r.Content]; ok {
			continue
		}
		seen[r.Content] = struct{}{}
		out = append(out, r)
	}
	return out
}

// RRSetSnapshot renders an RRSet as the JSON audit before/after image. The
// wire content of MX/SRV records carries the embedded priority; the snapshot
// splits it back out so Before and After show the human form uniformly. It
// returns an empty string for a nil RRSet (e.g. create on a new RRSet or
// delete when the RRSet could not be fetched).
func RRSetSnapshot(rrset *models.RRSet) string {
	if rrset == nil {
		return ""
	}
	// Copy rather than mutate: callers reuse this RRSet for the PDNS PATCH,
	// whose content must keep the priority embedded.
	records := make([]models.RecordInfo, len(rrset.Records))
	for i, r := range rrset.Records {
		records[i] = r
		// Only content that still carries the FULL wire field count has the
		// priority embedded: MX wire "10 mail." has 2 fields vs 1 once
		// split, SRV wire "10 20 5060 sip." has 4 vs 3. Records read back
		// from PowerDNS through ListRecords already had their priority
		// detached — re-splitting those shifts the SRV weight into the
		// priority field and drops it from the content.
		if wire := models.TypeWireFields(rrset.Type); wire > 0 &&
			len(strings.Fields(r.Content)) >= wire {
			if p, c, ok := models.SplitPriority(rrset.Type, r.Content); ok {
				records[i].Content = c
				records[i].Priority = p
			}
		}
	}
	snapshot := *rrset
	snapshot.Records = records
	b, err := json.Marshal(snapshot)
	if err != nil {
		return ""
	}
	return string(b)
}

// storedComments returns the Items of an RRSet's comment patch, or nil when
// the RRSet carries no comments (or there is no RRSet to read them from).
func storedComments(rrset *models.RRSet) []models.Comment {
	if rrset == nil || rrset.Comments == nil {
		return nil
	}
	return rrset.Comments.Items
}

// reconcileCommentMetadata enforces the server-ownership invariant for RRSet
// comment metadata: Account and ModifiedAt are never taken from the client.
// Each submitted item is matched one-to-one, in order (FIFO), against the
// stored comments of the same RRSet with EXACTLY equal Content; on a match
// the item inherits the stored metadata, otherwise both fields are zeroed
// (""/0) so PowerDNS stamps modified_at for the new comment. Duplicate
// stored comments are consumed first-match-first-served, so an echoed list
// keeps each duplicate's own metadata. A nil patch and a Clear patch are
// strict no-ops.
//
// Callers pass the stored comments from the before-image fetch. When that
// fetch fails or finds nothing, the stored list is empty and every submitted
// item is zeroed — the degraded path (e.g. UpdateRecord's best-effort
// pre-read): client-supplied metadata is dropped rather than forwarded
// verbatim, which is always safe because PowerDNS re-stamps modified_at on
// write.
func reconcileCommentMetadata(patch *models.CommentPatch, stored []models.Comment) {
	if patch == nil || patch.Clear {
		return
	}
	consumed := make([]bool, len(stored))
	for i := range patch.Items {
		item := &patch.Items[i]
		matched := false
		for j := range stored {
			if consumed[j] || stored[j].Content != item.Content {
				continue
			}
			consumed[j] = true
			item.Account = stored[j].Account
			item.ModifiedAt = stored[j].ModifiedAt
			matched = true
			break
		}
		if !matched {
			item.Account = ""
			item.ModifiedAt = 0
		}
	}
}

// ValidateRecordSet validates and canonicalises an RRSet for a write: the
// type (uppercase + whitelist), the TTL (non-negative), a non-empty record
// list (an RRSet with zero records is not a writable object — deleting one
// is a separate operation), the name (syntax) and each record's content and
// priority (bare form — priority carried in RecordInfo.Priority). It
// canonicalises the name against the zone but does
// NOT normalise record content; PrepareRecordContent runs later so a
// merge-then-normalise write path keeps each record's priority in the
// Priority field until the single final pass (PrepareRecordContent is not
// idempotent for MX/SRV).
func ValidateRecordSet(rrset *models.RRSet, zoneID string) error {
	rrset.Type = CanonicalRecordType(rrset.Type)
	if err := validators.ValidateRecordType(rrset.Type); err != nil {
		return err
	}
	if err := validators.ValidateRecordTTL(rrset.TTL); err != nil {
		return err
	}
	if len(rrset.Records) == 0 {
		return fmt.Errorf("at least one record is required; use delete_record / DELETE to remove an RRSet")
	}
	if err := validators.ValidateRecordName(rrset.Name); err != nil {
		return err
	}
	for i := range rrset.Records {
		if err := validators.ValidateRecordContent(rrset.Type, rrset.Records[i].Content); err != nil {
			return err
		}
		if err := validators.ValidateRecordPriority(rrset.Type, rrset.Records[i].Priority); err != nil {
			return err
		}
	}
	rrset.Name = NormalizeRecordName(rrset.Name, zoneID)
	return nil
}

// PrepareValidatedRecordSet validates the RRSet (ValidateRecordSet) and then
// normalises each record's content in the same pass (PrepareRecordContent).
// This is the validate+normalize path for a plain REPLACE write, where no
// merge happens and content normalisation can run immediately.
func PrepareValidatedRecordSet(rrset *models.RRSet, zoneID string) error {
	if err := ValidateRecordSet(rrset, zoneID); err != nil {
		return err
	}
	for i := range rrset.Records {
		content, prio, err := PrepareRecordContent(rrset.Type, rrset.Records[i].Content, rrset.Records[i].Priority)
		if err != nil {
			return err
		}
		rrset.Records[i].Content, rrset.Records[i].Priority = content, prio
	}
	return nil
}

// ListRecords returns the RRSets of a zone, optionally filtered to one name
// (and type). The name must already be canonical (NormalizeRecordName);
// rrType requires name, mirroring the PowerDNS rrset_name/rrset_type query
// parameter pair.
func (s *Service) ListRecords(ctx context.Context, user *models.User, zoneID, name, rrType string) ([]models.RRSet, error) {
	if err := s.authorizeZone(ctx, user, zoneID); err != nil {
		return nil, err
	}
	if name == "" {
		return s.PDNS.ListRecords(ctx, zoneID)
	}
	return s.PDNS.ListRecord(ctx, zoneID, name, rrType)
}

// CreateRecord appends a record to a zone (POST semantics): it merges the
// submission into any existing RRSet of the same name+type, preserving
// sibling records, then normalises content once, deduplicates and PATCHes.
// An unspecified TTL inherits the existing RRSet's TTL on a merge (so
// pre-existing siblings keep theirs) or DefaultRecordTTL.
//
// rrset must be validated first (ValidateRecordSet — without content
// normalisation, so each record keeps its priority until the merge is done).
// The whole fetch→merge→PATCH sequence holds the per-zone lock, serializing
// against concurrent writers through any transport.
func (s *Service) CreateRecord(ctx context.Context, user *models.User, zoneID string, rrset models.RRSet, src Source) error {
	if err := s.authorizeZone(ctx, user, zoneID); err != nil {
		return err
	}

	// Serialize the fetch→merge→PATCH sequence against concurrent writers on
	// the same zone, including writers served by another GoZone instance.
	release, err := s.locks.Lock(ctx, zoneID)
	if err != nil {
		return &StageError{Stage: StageLock, Err: err}
	}
	defer release()

	// Merge with any existing RRSet so sibling records are preserved. Content
	// normalization runs AFTER the merge so each record keeps its original
	// priority in the Priority field until the final PrepareRecordContent
	// pass (PrepareRecordContent is not idempotent for MX/SRV, so
	// normalizing the new records before the merge would lose their
	// priority).
	allRecords, err := s.PDNS.ListRecords(ctx, zoneID)
	if err != nil {
		return &StageError{Stage: StageFetch, Err: err}
	}
	var existingRRSet models.RRSet
	foundExisting := false
	for _, rr := range allRecords {
		if RRSetsMatch(rr.Name, rr.Type, rrset.Name, rrset.Type) {
			existingRRSet = rr
			foundExisting = true
			rrset.Records = append(append([]models.RecordInfo{}, rr.Records...), rrset.Records...)
			break
		}
	}
	for i := range rrset.Records {
		content, prio, err := PrepareRecordContent(rrset.Type, rrset.Records[i].Content, rrset.Records[i].Priority)
		if err != nil {
			return err
		}
		rrset.Records[i].Content, rrset.Records[i].Priority = content, prio
	}
	// Deduplicate after normalisation: a payload record whose wire content
	// matches an existing sibling of the RRSet would make the merged PATCH
	// carry a duplicate record, which PowerDNS rejects with an opaque 422.
	// The first occurrence wins, so existing records keep their flags.
	rrset.Records = DedupRecordsByContent(rrset.Records)

	// Resolve an unspecified (zero) TTL: inherit the existing RRSet's TTL on
	// a merge (PowerDNS applies the RRSet-level TTL to every record of the
	// set, so submitting 0 would silently zero the TTL of the pre-existing
	// sibling records), else the 3600 default. The inheritance deliberately
	// has no positive guard: there is no cache between the caller and this
	// service, so a deliberate no-cache (TTL 0) RRSet must stay 0 instead of
	// being silently upgraded to the default. Negative values were rejected
	// at validation.
	if rrset.TTL <= 0 {
		rrset.TTL = DefaultRecordTTL
		if foundExisting {
			rrset.TTL = existingRRSet.TTL
		}
	}

	// Comment metadata is server-owned: reconcile the submitted comments
	// against the stored RRSet's (a brand-new RRSet has none, so every item
	// is zeroed for PowerDNS to stamp).
	reconcileCommentMetadata(rrset.Comments, storedComments(&existingRRSet))

	if err := s.PDNS.UpdateRecord(ctx, zoneID, rrset); err != nil {
		return &StageError{Stage: StagePatch, Err: err}
	}

	// Audit trail: before/after snapshots; old is empty when the RRSet is
	// brand new. The one-liner carries the last record's content, read
	// defensively so a malformed submission can never panic the write path.
	lastContent := ""
	if n := len(rrset.Records); n > 0 {
		lastContent = rrset.Records[n-1].Content
	}
	var oldSnapshot *models.RRSet
	if foundExisting {
		oldSnapshot = &existingRRSet
	}
	if err := LogActivity(ctx, s.DB, ActivityEntry{
		UserID:   userIDOf(user),
		ZoneID:   zoneID,
		Action:   "create_record",
		Details:  fmt.Sprintf("Created %s record %s -> %s via %s", rrset.Type, rrset.Name, lastContent, src.Label()),
		OldValue: RRSetSnapshot(oldSnapshot),
		NewValue: RRSetSnapshot(&rrset),
	}); err != nil {
		logger.Error("failed to log create_record activity", "zone_id", zoneID, "error", err)
	}
	return nil
}

// UpdateRecord replaces a record (RRSet) in a zone (REPLACE semantics,
// idempotent). rrset must already be validated and fully normalised
// (PrepareValidatedRecordSet); this method resolves the TTL (inheriting the
// replaced RRSet's when unspecified), takes the audit before-image, PATCHes
// and logs. The whole snapshot→PATCH sequence holds the per-zone lock: the
// replace reads state (before-image, TTL inheritance) before writing, so a
// concurrent append's fetch→merge→PATCH cycle could otherwise rewrite the
// pre-replace state and silently lose the update.
func (s *Service) UpdateRecord(ctx context.Context, user *models.User, zoneID string, rrset models.RRSet, src Source) error {
	if err := s.authorizeZone(ctx, user, zoneID); err != nil {
		return err
	}

	// Serialize the snapshot→PATCH sequence against every other read-modify-
	// write on the same zone, including writers served by another instance.
	release, err := s.locks.Lock(ctx, zoneID)
	if err != nil {
		return &StageError{Stage: StageLock, Err: err}
	}
	defer release()

	// Best-effort snapshot of the RRSet being replaced, for the audit trail.
	// A fetch failure (or a brand-new RRSet) leaves old_value empty — the
	// REPLACE itself must not fail because the audit's before-image is
	// unavailable.
	var oldRRSet *models.RRSet
	if existing, err := s.PDNS.ListRecord(ctx, zoneID, rrset.Name, rrset.Type); err == nil && len(existing) > 0 {
		oldRRSet = &existing[0]
	}

	// Resolve an unspecified (zero) TTL: inherit the TTL of the RRSet being
	// replaced, else the 3600 default. A REPLACE carrying ttl 0 would zero
	// the whole set.
	if rrset.TTL <= 0 {
		rrset.TTL = DefaultRecordTTL
		if oldRRSet != nil && oldRRSet.TTL > 0 {
			rrset.TTL = oldRRSet.TTL
		}
	}

	// Comment metadata is server-owned: reconcile the submitted comments
	// against the replaced RRSet's stored ones. The pre-read is best-effort —
	// when it failed or found nothing the stored list is empty and every
	// submitted item is zeroed (the degraded path, see reconcileCommentMetadata).
	reconcileCommentMetadata(rrset.Comments, storedComments(oldRRSet))

	if err := s.PDNS.UpdateRecord(ctx, zoneID, rrset); err != nil {
		return &StageError{Stage: StagePatch, Err: err}
	}

	if err := LogActivity(ctx, s.DB, ActivityEntry{
		UserID:   userIDOf(user),
		ZoneID:   zoneID,
		Action:   "update_record",
		Details:  fmt.Sprintf("Updated %s record %s via %s", rrset.Type, rrset.Name, src.Label()),
		OldValue: RRSetSnapshot(oldRRSet),
		NewValue: RRSetSnapshot(&rrset),
	}); err != nil {
		logger.Error("failed to log update_record activity", "zone_id", zoneID, "error", err)
	}
	return nil
}

// DeleteRecord deletes a record (RRSet) from a zone by canonical name and
// type, taking the audit before-image first (best-effort, like the other
// write paths). The snapshot→PATCH sequence holds the per-zone lock like
// UpdateRecord: a concurrent append whose fetch happened before the delete
// would otherwise re-PATCH the deleted record back into existence.
func (s *Service) DeleteRecord(ctx context.Context, user *models.User, zoneID, name, rrType string, src Source) error {
	if err := s.authorizeZone(ctx, user, zoneID); err != nil {
		return err
	}

	release, err := s.locks.Lock(ctx, zoneID)
	if err != nil {
		return &StageError{Stage: StageLock, Err: err}
	}
	defer release()

	// Best-effort snapshot of the RRSet before deletion, for the audit trail.
	var oldRRSet *models.RRSet
	if existing, err := s.PDNS.ListRecord(ctx, zoneID, name, rrType); err == nil && len(existing) > 0 {
		oldRRSet = &existing[0]
	}

	if err := s.PDNS.DeleteRecord(ctx, zoneID, name, rrType); err != nil {
		return &StageError{Stage: StagePatch, Err: err}
	}

	if err := LogActivity(ctx, s.DB, ActivityEntry{
		UserID:   userIDOf(user),
		ZoneID:   zoneID,
		Action:   "delete_record",
		Details:  fmt.Sprintf("Deleted %s record %s via %s", rrType, name, src.Label()),
		OldValue: RRSetSnapshot(oldRRSet),
	}); err != nil {
		logger.Error("failed to log delete_record activity", "zone_id", zoneID, "error", err)
	}
	return nil
}
