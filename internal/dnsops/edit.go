package dnsops

import (
	"context"
	"fmt"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/models"
)

// RecordConflictError marks a concurrent-modification conflict — the
// before-image submitted by the client (original content/priority) no longer
// matches the stored RRSet — so web callers answer 409 and the client reloads
// instead of the edit silently duplicating or resurrecting records. The
// concept used to live in the web handler; the service owns it now so every
// transport classifies a stale before-image the same way. It is deliberately
// NOT a StageError: a refused edit never reached PowerDNS, so there is no
// composite stage to tag.
type RecordConflictError struct {
	Message string
}

func (e *RecordConflictError) Error() string { return e.Message }

// EditRecordInput carries one record edit (the web update form semantics):
// the submitted RRSet holds exactly one record — the edited content, priority
// and disabled flag — plus the identity (OriginalContent/OriginalPriority) of
// the record it replaces, i.e. the before-image the client rendered. An empty
// OriginalContent designates a create-through-edit of a brand-new RRSet.
type EditRecordInput struct {
	RRSet            models.RRSet
	OriginalContent  string
	OriginalPriority int
}

// EditRecord applies a single-record edit to a zone, owning the exact
// stale-edit transition table the web update form implemented historically:
//
//   - no existing RRSet + submitted identity  -> RecordConflictError (the
//     record was deleted while the page was open; refuse instead of
//     resurrecting it).
//   - no existing RRSet + no identity         -> create the submitted record.
//   - identity matches a record of the RRSet  -> replace it in place, keeping
//     its siblings (sibling-preserving REPLACE).
//   - identity matches nothing on a singleton
//     SOA RRSet                               -> replace the sole record:
//     SOA-EDIT bumps the serial between page load and save, so every SOA
//     edit's submitted identity is stale by construction — conflicting here
//     would make SOA edits impossible.
//   - otherwise                               -> RecordConflictError (another
//     writer changed the set; appending would leave the old record next to
//     the edited copy).
//
// The merge happens BEFORE content normalisation so each record keeps its
// priority in the Priority field until the single final PrepareRecordContent
// pass (which is not idempotent for MX/SRV). The record the edit maps to is
// tracked by its position; after the merge→normalise→dedup pipeline it is
// re-pointed at the surviving (first) occurrence — an edit can collapse its
// record onto a sibling, and the returned display record must be the survivor.
//
// TTL resolution: an explicit TTL (RRSet.TTL > 0) wins; otherwise the existing
// RRSet's TTL is inherited — INCLUDING 0, because there is no cache between
// the form and the service: a deliberate no-cache (TTL 0) RRSet must not
// silently become DefaultRecordTTL just because the operator left the field
// blank; otherwise DefaultRecordTTL applies.
//
// On success it returns the wire-form RRSet that was PATCHed and the edited
// record in display form (SplitPriority applied, the value the web inline
// editor echoes back into its row).
func (s *Service) EditRecord(ctx context.Context, user *models.User, zoneID string, in EditRecordInput, src Source) (*models.RRSet, models.RecordInfo, error) {
	if err := s.authorizeZone(ctx, user, zoneID); err != nil {
		return nil, models.RecordInfo{}, err
	}

	// Serialize the fetch→merge→PATCH sequence against concurrent writers on
	// the same zone, including writers served by another GoZone instance.
	release, err := s.locks.Lock(ctx, zoneID)
	if err != nil {
		return nil, models.RecordInfo{}, &StageError{Stage: StageLock, Err: err}
	}
	defer release()

	allRecords, err := s.PDNS.ListRecords(ctx, zoneID)
	if err != nil {
		return nil, models.RecordInfo{}, &StageError{Stage: StageFetch, Err: err}
	}

	var existingRRSet *models.RRSet
	for i := range allRecords {
		if RRSetsMatch(allRecords[i].Name, allRecords[i].Type, in.RRSet.Name, in.RRSet.Type) {
			existingRRSet = &allRecords[i]
			break
		}
	}

	submitted := in.RRSet.Records[0]

	// Identity position: which record of the merged set this edit maps to,
	// tracked BEFORE normalisation/dedup rewrites contents and shrinks the
	// slice. The inline editor echoes this record back to the row.
	updatedIdx := 0
	var updatedRecords []models.RecordInfo
	switch {
	case existingRRSet == nil && in.OriginalContent != "":
		// An original identity on a missing RRSet means the record was
		// deleted (or its RRSet changed) after the form was rendered. Refuse
		// rather than silently recreating it; omitting the identity is the
		// explicit create path.
		return nil, models.RecordInfo{}, &RecordConflictError{
			Message: "This record was deleted (or its RRSet changed) since the page was loaded. Reload the page and retry your edit.",
		}
	case existingRRSet == nil:
		updatedRecords = []models.RecordInfo{submitted}
	case recordIdentityMatches(existingRRSet, in.OriginalContent, in.OriginalPriority):
		updatedRecords, updatedIdx = mergeRecordIntoRRSet(existingRRSet.Records, in.OriginalContent, in.OriginalPriority, submitted)
	case in.RRSet.Type == "SOA" && len(existingRRSet.Records) == 1:
		// An SOA edit is always stale this way: PowerDNS bumps the serial
		// via SOA-EDIT between page load and save, so the submitted original
		// content no longer matches. Replace the sole record instead of
		// appending a second one, which PowerDNS rejects.
		updatedRecords = []models.RecordInfo{submitted}
	default:
		// The live RRSet no longer contains the submitted identity. For a
		// singleton that means another writer removed or replaced it; for a
		// multi-record set appending would leave the old record next to the
		// edited copy. Refuse and ask the client to reload.
		return nil, models.RecordInfo{}, &RecordConflictError{
			Message: "This record was modified by someone else (or its content changed) since the page was loaded. Reload the page and retry your edit.",
		}
	}

	// Normalise each record exactly once, AFTER the merge, so the edited
	// record keeps its priority in the Priority field until this pass
	// (PrepareRecordContent is not idempotent for MX/SRV).
	for i := range updatedRecords {
		content, prio, err := PrepareRecordContent(in.RRSet.Type, updatedRecords[i].Content, updatedRecords[i].Priority)
		if err != nil {
			return nil, models.RecordInfo{}, err
		}
		updatedRecords[i].Content, updatedRecords[i].Priority = content, prio
	}

	// The edit can collapse a record onto a sibling of the same RRSet (e.g.
	// both A records now hold the same address). RRSets are a set — duplicate
	// contents are meaningless and PowerDNS rejects them — so dedup exactly
	// like the create and batch paths do. The first occurrence wins, so the
	// record the edit saved may now sit at an earlier index than the one it
	// replaced: re-point updatedIdx at the surviving record, defensively
	// falling back to the first record.
	editedContent := updatedRecords[updatedIdx].Content
	updatedRecords = DedupRecordsByContent(updatedRecords)
	updatedIdx = 0
	for i, rec := range updatedRecords {
		if rec.Content == editedContent {
			updatedIdx = i
			break
		}
	}

	// Resolve the TTL: an explicit value wins; otherwise inherit the existing
	// RRSet's TTL — PowerDNS applies the RRSet-level TTL to every record of
	// the set, so defaulting here would silently rewrite the siblings'
	// deliberately short (or no-cache zero) TTL — else the default.
	ttl := in.RRSet.TTL
	if ttl <= 0 {
		ttl = DefaultRecordTTL
		if existingRRSet != nil {
			ttl = existingRRSet.TTL
		}
	}

	newRRSet := &models.RRSet{
		Name:     in.RRSet.Name,
		Type:     in.RRSet.Type,
		TTL:      ttl,
		Records:  updatedRecords,
		Comments: in.RRSet.Comments,
	}

	if err := s.PDNS.UpdateRecord(ctx, zoneID, *newRRSet); err != nil {
		return nil, models.RecordInfo{}, &StageError{Stage: StagePatch, Err: err}
	}

	if err := LogActivity(ctx, s.DB, ActivityEntry{
		UserID:   userIDOf(user),
		ZoneID:   zoneID,
		Action:   "update_record",
		Details:  fmt.Sprintf("Updated %s record %s via %s", newRRSet.Type, newRRSet.Name, src.Label()),
		OldValue: RRSetSnapshot(existingRRSet),
		NewValue: RRSetSnapshot(newRRSet),
	}); err != nil {
		logger.Error("failed to log update_record activity", "zone_id", zoneID, "error", err)
	}

	// Display form of the saved record: SplitPriority applied, so the web
	// inline editor can resync its row (data-original-content/priority and
	// the Delete form) from the normalised value rather than the wire form.
	updated := newRRSet.Records[updatedIdx]
	if p, c, ok := models.SplitPriority(newRRSet.Type, updated.Content); ok {
		updated.Priority = p
		updated.Content = c
	}
	return newRRSet, updated, nil
}

// recordIdentityMatches reports whether the RRSet holds a record whose
// content+priority equal the submitted before-image.
func recordIdentityMatches(rrset *models.RRSet, content string, priority int) bool {
	for _, rec := range rrset.Records {
		if rec.Content == content && rec.Priority == priority {
			return true
		}
	}
	return false
}

// mergeRecordIntoRRSet replaces the record matching originalContent+originalPriority
// with replacement, keeping every sibling in place, and returns the merged
// slice plus the index the replacement landed at. The identity is guaranteed
// to match by the caller's transition table.
func mergeRecordIntoRRSet(existing []models.RecordInfo, originalContent string, originalPriority int, replacement models.RecordInfo) ([]models.RecordInfo, int) {
	result := make([]models.RecordInfo, len(existing))
	copy(result, existing)
	for i, r := range result {
		if r.Content == originalContent && r.Priority == originalPriority {
			result[i] = replacement
			return result, i
		}
	}
	result = append(result, replacement)
	return result, len(result) - 1
}
