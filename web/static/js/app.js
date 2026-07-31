// gozone - PowerDNS Admin Interface
console.log('gozone - PowerDNS Admin Interface');

var SUN_SVG = '<svg aria-hidden="true" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
var MOON_SVG = '<svg aria-hidden="true" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';

function updateThemeIcon() {
    var isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    var svg = isDark ? MOON_SVG : SUN_SVG;
    var buttons = document.querySelectorAll('.theme-toggle');
    for (var i = 0; i < buttons.length; i++) {
        buttons[i].innerHTML = svg;
    }
}

(function() {
    // The colour theme is applied in <head> by theme.js (FOUC fix); here we
    // restore the persisted sidebar state and paint the theme-toggle icon,
    // both of which need the <body> DOM that is present once app.js runs at the
    // end of <body>.
    var collapsed = localStorage.getItem('gozone-sidebar') === 'true';
    if (collapsed) {
        document.body.classList.add('sidebar-collapsed');
    }

    updateThemeIcon();
})();

function toggleTheme() {
    var current = document.documentElement.getAttribute('data-theme');
    var next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('gozone-theme', next);
    updateThemeIcon();
}

function toggleSidebar() {
    document.body.classList.toggle('sidebar-collapsed');
    var collapsed = document.body.classList.contains('sidebar-collapsed');
    localStorage.setItem('gozone-sidebar', collapsed);
}

function generateTSIGSecret() {
    var bytes = new Uint8Array(64);
    crypto.getRandomValues(bytes);
    var binary = '';
    for (var i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    var base64 = btoa(binary);
    var keyEl = document.getElementById('key');
    if (keyEl) keyEl.value = base64;
    var algo = document.getElementById('algorithm');
    if (algo) {
        algo.value = 'hmac-sha512';
    }
}

function editRecordRow(btn) {
    var row = btn.closest('tr');
    toggleEditMode(row, true);
}

function cancelEditRow(btn) {
    var row = btn.closest('tr');
    toggleEditMode(row, false);
    resetRowValues(row);
}

function toggleEditMode(row, editing) {
    var displayEls = row.querySelectorAll('.rv');
    var editEls = row.querySelectorAll('.ev');
    // Toggle a .hidden class (display:none) rather than mutating inline
    // style.display: the edit fields start hidden via the same class, and
    // classList keeps the markup free of inline styles (CSP style-src has no
    // 'unsafe-inline').
    for (var i = 0; i < displayEls.length; i++) displayEls[i].classList.toggle('hidden', editing);
    for (var j = 0; j < editEls.length; j++) editEls[j].classList.toggle('hidden', !editing);
}

function resetRowValues(row) {
    var editContent = row.querySelector('.ev-content');
    var editTTL = row.querySelector('.ev-ttl');
    var editPrio = row.querySelector('.ev-prio');
    var editDisabled = row.querySelector('.ev-disabled');
    var editComments = row.querySelector('.ev-comments');
    var editCommentClear = row.querySelector('.ev-comment-clear-cb');

    var origContent = row.querySelector('.rv-content');
    var origTTL = row.querySelector('.rv-ttl');
    var origPrio = row.querySelector('.rv-prio');
    var origComments = row.querySelector('.rv-comments');

    if (editContent && origContent) editContent.value = origContent.textContent;
    if (editTTL && origTTL) editTTL.value = origTTL.textContent;
    if (editPrio && origPrio) editPrio.value = (origPrio.textContent === '-' ? '0' : origPrio.textContent);
    if (editDisabled) editDisabled.checked = row.getAttribute('data-disabled') === 'true';
    if (editComments && origComments) editComments.value = origComments.textContent;
    if (editCommentClear) editCommentClear.checked = false;
}

function showNotification(message, type) {
    var el = document.getElementById('notification');
    if (!el) {
        // Fallback for pages without the notification container
        console.error(message);
        return;
    }
    el.textContent = message;
    el.className = 'notification notification-' + (type || 'error');
    el.style.display = 'block';
    setTimeout(function() {
        el.style.display = 'none';
        el.textContent = '';
    }, 5000);
}

function saveRecordRow(btn) {
    var row = btn.closest('tr');
    var zoneID = row.getAttribute('data-zone-id');
    var csrfToken = row.getAttribute('data-csrf');
    var name = row.getAttribute('data-name');
    var recordType = row.getAttribute('data-type');
    var content = row.querySelector('.ev-content').value.trim();
    var ttl = row.querySelector('.ev-ttl').value;
    var prio = row.querySelector('.ev-prio').value;
    var disabled = row.querySelector('.ev-disabled') ? row.querySelector('.ev-disabled').checked : false;
    var comment = row.querySelector('.ev-comments') ? row.querySelector('.ev-comments').value : '';
    var commentClear = row.querySelector('.ev-comment-clear-cb') ? row.querySelector('.ev-comment-clear-cb').checked : false;

    if (!content) { showNotification('Content is required', 'error'); return; }

    var formData = new URLSearchParams();
    if (csrfToken) formData.append('gorilla.csrf.Token', csrfToken);
    formData.append('name', name);
    formData.append('type', recordType);
    formData.append('content', content);
    formData.append('ttl', ttl);
    formData.append('priority', prio);
    formData.append('disabled', disabled ? 'true' : 'false');
    formData.append('original_content', row.getAttribute('data-original-content'));
    formData.append('original_priority', row.getAttribute('data-original-priority'));
    formData.append('comment', comment);
    if (commentClear) formData.append('comment_clear', '1');

    fetch('/zones/' + zoneID + '/records/inline-update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
    })
    .then(function(resp) {
        if (!resp.ok) {
            return resp.text().then(function(text) {
                throw new Error('HTTP ' + resp.status + (text ? ': ' + text : ''));
            });
        }
        // Session expired: the auth middleware 303-redirects to /login, which
        // fetch follows transparently, so resp is now the HTML login page (200)
        // and resp.json() would throw an opaque "Unexpected token <". Detect the
        // redirect and surface a clear, actionable message instead.
        if (resp.redirected) {
            throw new Error('Session expired. Please reload the page to log in again.');
        }
        var ct = resp.headers.get('Content-Type') || '';
        if (ct.indexOf('application/json') === -1) {
            throw new Error('Unexpected response from server (not JSON).');
        }
        return resp.json();
    })
    .then(function(data) {
        if (data.success) {
            var r = data.record;
            row.querySelector('.rv-content').textContent = content;
            row.querySelector('.rv-ttl').textContent = ttl;
            row.querySelector('.rv-prio').textContent = (prio > 0 ? prio : '-');
            var statusCell = row.querySelector('.rv-status');
            if (r.records && r.records[0]) {
                if (r.records[0].disabled) {
                    statusCell.innerHTML = '<span class="badge badge-disabled">Disabled</span>';
                    row.setAttribute('data-disabled', 'true');
                } else {
                    statusCell.innerHTML = '<span class="badge badge-active">Active</span>';
                    row.setAttribute('data-disabled', 'false');
                }
            }
            var rvComments = row.querySelector('.rv-comments');
            var trimmedComment = comment.replace(/^\s+|\s+$/g, '');
            if (commentClear) {
                if (rvComments && rvComments.parentNode) {
                    rvComments.parentNode.removeChild(rvComments);
                }
            } else if (rvComments) {
                if (trimmedComment) {
                    if (rvComments.parentNode) {
                        rvComments.textContent = trimmedComment + '\n';
                    }
                } else if (rvComments.parentNode) {
                    rvComments.parentNode.removeChild(rvComments);
                }
            } else if (trimmedComment) {
                // No read-only comment block exists yet — create one. Since
                // the dedicated Comment column landed in zone_view.html,
                // .ev-comments lives in the .col-comment cell, NOT in the
                // Content cell. Insert the new read-only block into the
                // comment cell, before the edit textarea, so the
                // read-only block stays visually paired with the textarea
                // that created it. (Previously this code inserted into
                // row.querySelector('.ev-content').parentNode — the
                // Content cell — which raised DOMException
                // "Node.insertBefore: Child to insert before is not a
                // child of this node" because .ev-comments no longer
                // belongs to that cell after the column split.)
                var commentCell = row.querySelector('.ev-comments').parentNode;
                var newRv = document.createElement('div');
                newRv.className = 'rv rv-comments record-comments';
                newRv.textContent = trimmedComment + '\n';
                var editComments = row.querySelector('.ev-comments');
                commentCell.insertBefore(newRv, editComments);
            }
            var clearCb = row.querySelector('.ev-comment-clear-cb');
            if (clearCb) clearCb.checked = false;
            row.setAttribute('data-original-content', content);
            row.setAttribute('data-original-priority', prio);
            toggleEditMode(row, false);
            showNotification('Record updated', 'success');
        } else {
            showNotification('Error: ' + (data.error || 'Unknown error'), 'error');
        }
    })
    .catch(function(err) {
        showNotification('Request failed: ' + err.message, 'error');
    });
}

function addRecordRow() {
    var container = document.getElementById('record-rows');
    var rows = container.querySelectorAll('.record-row');
    var template = rows[0].cloneNode(true);
    var idx = rows.length;
    // Re-scope label associations to unique ids for the cloned row (m54):
    // cloneNode would otherwise duplicate the template row's ids, breaking the
    // for/id pairing and producing invalid HTML. Each id/for ends with the
    // template row's index (0); rewrite the trailing "-<n>" to the new index.
    var labels = template.querySelectorAll('label[for]');
    for (var k = 0; k < labels.length; k++) {
        labels[k].setAttribute('for', labels[k].getAttribute('for').replace(/-\d+$/, '-' + idx));
    }
    var idEls = template.querySelectorAll('[id]');
    for (var m = 0; m < idEls.length; m++) {
        idEls[m].setAttribute('id', idEls[m].getAttribute('id').replace(/-\d+$/, '-' + idx));
    }
    var inputs = template.querySelectorAll('input[type=text], input[type=number]');
    for (var i = 0; i < inputs.length; i++) {
        if (inputs[i].name === 'ttl') {
            inputs[i].value = '3600';
        } else if (inputs[i].name === 'priority') {
            inputs[i].value = '0';
        } else {
            inputs[i].value = '';
        }
    }
    var textareas = template.querySelectorAll('textarea');
    for (var j = 0; j < textareas.length; j++) {
        textareas[j].value = '';
    }
    var select = template.querySelector('select[name=type]');
    if (select) select.value = select.querySelector('option').value;
    var prioGrp = template.querySelector('.record-prio-group');
    if (prioGrp) prioGrp.classList.add('hidden');
    container.appendChild(template);
}

function copyAPIKey() {
    var reveal = document.querySelector('.api-key-reveal');
    if (!reveal) return;
    var text = reveal.getAttribute('data-key');
    if (!text) return;
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(function() {
            updateCopyButton(reveal);
        });
        return;
    }
    // Fallback for non-secure contexts (plain HTTP). #nosec G103 -- not used for exec of untrusted input
    var ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    updateCopyButton(reveal);
}

function updateCopyButton(reveal) {
    var btn = reveal.querySelector('.btn');
    if (btn) {
        btn.textContent = 'Copied!';
        setTimeout(function() { btn.textContent = 'Copy'; }, 2000);
    }
}

function toggleTemplateVars(select) {
    var targetId = select.getAttribute('data-target') || 'template-vars';
    var target = document.getElementById(targetId);
    if (!target) return;
    target.style.display = select.value ? 'block' : 'none';
}

function applyPerPage(select) {
    var prefix = select.getAttribute('data-prefix') || '';
    // Merge into the current query so the other section's pagination (and any
    // search) is preserved; only this section's page size changes and its page
    // resets to 1.
    var params = new URLSearchParams(window.location.search);
    params.set(prefix + 'PerPage', select.value);
    params.delete(prefix + 'Page');
    var searchInput = document.querySelector('input[name=search]');
    if (searchInput) {
        if (searchInput.value) {
            params.set('search', searchInput.value);
        } else {
            params.delete('search');
        }
    }
    window.location.href = '?' + params.toString();
}

function togglePriority(select) {
    var t = select.value;
    var row = select.closest('.record-row');
    if (!row) return;
    var grp = row.querySelector('.record-prio-group');
    if (!grp) return;
    // Toggle .hidden (display:none) instead of inline style.display so no
    // inline style attribute is left behind (CSP style-src has no
    // 'unsafe-inline').
    grp.classList.toggle('hidden', !(t === 'MX' || t === 'SRV'));
}

function initRecordPriority() {
    var selects = document.querySelectorAll('select[data-action="toggle-priority"]');
    for (var i = 0; i < selects.length; i++) {
        togglePriority(selects[i]);
    }
}

// Surface zone-import feedback carried via the ?import_skipped query param set
// by ImportZone when BIND lines could not be parsed (m28). Shows a one-shot
// warning notification, then strips the param so it does not recur on refresh.
function initImportFeedback() {
    var params = new URLSearchParams(window.location.search);
    var skipped = params.get('import_skipped');
    if (!skipped) return;
    showNotification('Import completed, but ' + skipped + ' line(s) could not be parsed and were skipped. See server logs for details.', 'warning');
    params.delete('import_skipped');
    var clean = params.toString();
    window.history.replaceState(null, '', clean ? '?' + clean : window.location.pathname);
}

// --- Bulk selection ---
//
// Every list view (zone records, zones, TSIG keys, API keys, users, groups,
// templates) exposes the same shape: per-row checkboxes, a header "select all"
// checkbox, a selected-count label, and a "Delete selected" button that POSTs
// the selection as form data and reloads on success. The seven previous
// hand-written, near-identical copies (~600 lines) collapse into one factory
// driven by a per-table spec.

// bulkFailedSuffix formats the "; N failed: a, b" tail appended to the success
// notification when a best-effort bulk delete skips some items.
function bulkFailedSuffix(n, list) {
    return '; ' + n + ' failed: ' + list.join(', ');
}

// makeBulkController builds the selection + delete helpers for one list table
// from a spec:
//   name           — short key used to reach this controller (e.g. 'records')
//   checkboxClass  — class on each row's checkbox (without the dot)
//   countId        — id of the selected-count label element
//   noun           — singular item noun, used for the count label, the
//                    "select at least one" warning and the "Deleted N <noun>(s)"
//                    success line
//   selectAllAction— data-action of the header "select all" checkbox
//   deleteAction   — data-action of the "Delete selected" button
//   barId          — id of the bulk-action bar (carries data-csrf and, for
//                    records, data-zone-id)
//   endpoint       — string URL, or function(bar) returning the URL
//   idField/idAttr — single-id families: form field name + row attribute holding
//                    the id (mutually exclusive with appendRowFields)
//   appendRowFields— override for multi-field rows (records: name/type/...),
//                    called as appendRowFields(formData, row)
//   confirmNoun    — noun used in the confirm dialog (defaults to noun; TSIG and
//                    API keys use the fuller "TSIG key"/"API key")
//   failedSuffix   — function(n, list) formatting the "; ... failed ..." tail,
//                    or null when the endpoint never reports failures (records)
function makeBulkController(spec) {
    function selectedRows() {
        var boxes = document.querySelectorAll('.' + spec.checkboxClass);
        var rows = [];
        for (var i = 0; i < boxes.length; i++) {
            if (boxes[i].checked) rows.push(boxes[i].closest('tr'));
        }
        return rows;
    }

    function updateCount() {
        var rows = selectedRows();
        var countEl = document.getElementById(spec.countId);
        if (countEl) {
            countEl.textContent = rows.length + ' ' + spec.noun + (rows.length === 1 ? '' : 's') + ' selected';
        }
        var selectAll = document.querySelector('[data-action="' + spec.selectAllAction + '"]');
        var boxes = document.querySelectorAll('.' + spec.checkboxClass);
        if (selectAll) {
            var allChecked = boxes.length > 0;
            for (var i = 0; i < boxes.length; i++) {
                if (!boxes[i].checked) { allChecked = false; break; }
            }
            selectAll.checked = allChecked;
        }
    }

    function toggleSelectAll(cb) {
        var boxes = document.querySelectorAll('.' + spec.checkboxClass);
        for (var i = 0; i < boxes.length; i++) boxes[i].checked = cb.checked;
        updateCount();
    }

    async function bulkDelete() {
        var rows = selectedRows();
        if (rows.length === 0) { showNotification('Select at least one ' + spec.noun + ' first', 'warning'); return; }
        var confirmNoun = spec.confirmNoun || spec.noun;
        if (!await confirmDialog('Delete ' + rows.length + ' selected ' + confirmNoun + '(s)? This cannot be undone.', { danger: true, confirmText: 'Delete' })) return;

        var bar = document.getElementById(spec.barId);
        var csrfToken = bar ? bar.getAttribute('data-csrf') : '';
        var endpoint = typeof spec.endpoint === 'function' ? spec.endpoint(bar) : spec.endpoint;

        var formData = new URLSearchParams();
        if (csrfToken) formData.append('gorilla.csrf.Token', csrfToken);
        for (var i = 0; i < rows.length; i++) {
            if (spec.appendRowFields) {
                spec.appendRowFields(formData, rows[i]);
            } else {
                formData.append(spec.idField, rows[i].getAttribute(spec.idAttr));
            }
        }

        fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: formData.toString()
        })
        .then(function(resp) {
            // Session expired: the auth middleware 303-redirects to /login, which
            // fetch follows transparently. Detect it and surface a clear message.
            if (resp.redirected) {
                throw new Error('Session expired. Please reload the page to log in again.');
            }
            var ct = resp.headers.get('Content-Type') || '';
            if (ct.indexOf('application/json') === -1) {
                throw new Error('Unexpected response from server (not JSON).');
            }
            return resp.json().then(function(data) {
                if (!resp.ok || !data.success) {
                    throw new Error(data.error || ('HTTP ' + resp.status));
                }
                return data;
            });
        })
        .then(function(data) {
            var msg = 'Deleted ' + data.deleted + ' ' + spec.noun + '(s)';
            if (spec.failedSuffix && data.failed && data.failed.length > 0) {
                msg += spec.failedSuffix(data.failed.length, data.failed);
            }
            showNotification(msg, data.failed && data.failed.length > 0 ? 'warning' : 'success');
            window.location.reload();
        })
        .catch(function(err) {
            showNotification('Delete failed: ' + err.message, 'error');
        });
    }

    return { selectedRows: selectedRows, updateCount: updateCount, toggleSelectAll: toggleSelectAll, bulkDelete: bulkDelete };
}

// One spec per list table. The records table is special: its endpoint is
// zone-scoped (read from the bar's data-zone-id), each row contributes four id
// fields (name/type/content/priority) instead of a single id, and the response
// carries only {deleted} (no failed list) — so it overrides endpoint/
// appendRowFields and sets failedSuffix=null.
var bulkSpecs = [
    {
        name: 'records',
        checkboxClass: 'record-select',
        countId: 'bulk-selected-count',
        noun: 'record',
        selectAllAction: 'select-all-records',
        deleteAction: 'bulk-delete-selected',
        barId: 'bulk-actions-bar',
        endpoint: function(bar) { return '/zones/' + bar.getAttribute('data-zone-id') + '/records/bulk-delete'; },
        appendRowFields: function(fd, row) {
            fd.append('name', row.getAttribute('data-name'));
            fd.append('type', row.getAttribute('data-type'));
            fd.append('original_content', row.getAttribute('data-original-content'));
            fd.append('original_priority', row.getAttribute('data-original-priority'));
        },
        failedSuffix: null
    },
    {
        name: 'zones',
        checkboxClass: 'zone-select', countId: 'bulk-zones-count', noun: 'zone',
        selectAllAction: 'select-all-zones', deleteAction: 'bulk-delete-zones',
        barId: 'bulk-zones-bar', endpoint: '/zones/bulk-delete',
        idField: 'zone_id', idAttr: 'data-zone-id', failedSuffix: bulkFailedSuffix
    },
    {
        name: 'tsig',
        checkboxClass: 'tsig-select', countId: 'bulk-tsig-count', noun: 'key',
        selectAllAction: 'select-all-tsig', deleteAction: 'bulk-delete-tsig',
        barId: 'bulk-tsig-bar', endpoint: '/tsigkeys/bulk-delete',
        idField: 'key_id', idAttr: 'data-key-id',
        confirmNoun: 'TSIG key', failedSuffix: bulkFailedSuffix
    },
    {
        name: 'apikeys',
        checkboxClass: 'apikey-select', countId: 'bulk-apikey-count', noun: 'key',
        selectAllAction: 'select-all-apikeys', deleteAction: 'bulk-delete-apikeys',
        barId: 'bulk-apikey-bar', endpoint: '/profile/api-keys/bulk-delete',
        idField: 'key_id', idAttr: 'data-key-id',
        confirmNoun: 'API key', failedSuffix: bulkFailedSuffix
    },
    {
        name: 'users',
        checkboxClass: 'user-select', countId: 'bulk-users-count', noun: 'user',
        selectAllAction: 'select-all-users', deleteAction: 'bulk-delete-users',
        barId: 'bulk-users-bar', endpoint: '/users/bulk-delete',
        idField: 'user_id', idAttr: 'data-user-id',
        failedSuffix: function(n, list) { return '; ' + n + ' skipped (self/last-admin): ' + list.join(', '); }
    },
    {
        name: 'groups',
        checkboxClass: 'group-select', countId: 'bulk-groups-count', noun: 'group',
        selectAllAction: 'select-all-groups', deleteAction: 'bulk-delete-groups',
        barId: 'bulk-groups-bar', endpoint: '/groups/bulk-delete',
        idField: 'group_id', idAttr: 'data-group-id', failedSuffix: bulkFailedSuffix
    },
    {
        name: 'templates',
        checkboxClass: 'template-select', countId: 'bulk-templates-count', noun: 'template',
        selectAllAction: 'select-all-templates', deleteAction: 'bulk-delete-templates',
        barId: 'bulk-templates-bar', endpoint: '/templates/bulk-delete',
        idField: 'template_id', idAttr: 'data-template-id',
        failedSuffix: function(n, list) { return '; ' + n + ' failed (built-in/missing): ' + list.join(', '); }
    }
];

// Build the controllers and the dispatcher lookup tables in one pass.
var bulkControllers = {};
var bulkDeleteByAction = {};
var bulkSelectAllByAction = {};
var bulkUpdateByCheckboxClass = {};
for (var i = 0; i < bulkSpecs.length; i++) {
    var ctrl = makeBulkController(bulkSpecs[i]);
    bulkControllers[bulkSpecs[i].name] = ctrl;
    bulkDeleteByAction[bulkSpecs[i].deleteAction] = ctrl.bulkDelete;
    bulkSelectAllByAction[bulkSpecs[i].selectAllAction] = ctrl.toggleSelectAll;
    bulkUpdateByCheckboxClass[bulkSpecs[i].checkboxClass] = ctrl.updateCount;
}

// bulkEditSelected flips every checked record row into inline edit mode. It is
// specific to the zone-records table (the other lists only support delete), so
// it stays standalone and reuses the records controller to read the selection.
function bulkEditSelected() {
    var rows = bulkControllers.records.selectedRows();
    if (rows.length === 0) { showNotification('Select at least one record first', 'warning'); return; }
    for (var i = 0; i < rows.length; i++) toggleEditMode(rows[i], true);
    showNotification(rows.length + (rows.length === 1 ? ' record' : ' records') + ' in edit mode', 'success');
}

// syncAllBulkCounts refreshes every list's count label + select-all indicator
// (called at init and after per-row checkbox changes affect the page).
function syncAllBulkCounts() {
    for (var i = 0; i < bulkSpecs.length; i++) {
        bulkControllers[bulkSpecs[i].name].updateCount();
    }
}

// --- Custom confirm dialog ---
//
// Replaces window.confirm (blocking, unthemeable, and announced inconsistently
// by screen readers). confirmDialog returns a Promise<boolean> so call sites
// can `await` it; the dialog is non-blocking, focus-trapped, and Escape cancels
// (REVIEW.md L-16d).
var confirmDialogEl = null;
var confirmDialogResolve = null;
var confirmDialogLastFocus = null;

function ensureConfirmDialog() {
    if (confirmDialogEl) return;
    confirmDialogEl = document.createElement('div');
    confirmDialogEl.className = 'modal-overlay';
    confirmDialogEl.style.display = 'none';
    confirmDialogEl.setAttribute('role', 'dialog');
    confirmDialogEl.setAttribute('aria-modal', 'true');
    confirmDialogEl.setAttribute('aria-labelledby', 'confirm-dialog-title');
    confirmDialogEl.setAttribute('aria-hidden', 'true');
    confirmDialogEl.innerHTML =
        '<div class="modal-dialog" role="document">' +
        '<h3 class="modal-title" id="confirm-dialog-title">Confirm</h3>' +
        '<p class="modal-message" id="confirm-dialog-message"></p>' +
        '<div class="modal-actions">' +
        '<button type="button" class="btn btn-secondary" data-confirm-cancel>Cancel</button>' +
        '<button type="button" class="btn btn-primary" data-confirm-ok>Confirm</button>' +
        '</div>' +
        '</div>';
    document.body.appendChild(confirmDialogEl);

    var okBtn = confirmDialogEl.querySelector('[data-confirm-ok]');
    var cancelBtn = confirmDialogEl.querySelector('[data-confirm-cancel]');
    okBtn.addEventListener('click', function() { closeConfirmDialog(true); });
    cancelBtn.addEventListener('click', function() { closeConfirmDialog(false); });
    confirmDialogEl.addEventListener('click', function(e) {
        // Click on the backdrop (the overlay itself, not its children) cancels.
        if (e.target === confirmDialogEl) closeConfirmDialog(false);
    });
    document.addEventListener('keydown', function(e) {
        if (!confirmDialogEl || confirmDialogEl.getAttribute('aria-hidden') === 'true') return;
        if (e.key === 'Escape') {
            e.preventDefault();
            closeConfirmDialog(false);
            return;
        }
        if (e.key === 'Tab') {
            // Keep focus cycling between the two action buttons while open.
            var group = [cancelBtn, okBtn];
            var idx = group.indexOf(document.activeElement);
            if (idx === -1) { e.preventDefault(); cancelBtn.focus(); return; }
            var next = e.shiftKey ? (idx - 1 + group.length) % group.length : (idx + 1) % group.length;
            e.preventDefault();
            group[next].focus();
        }
    });
}

function confirmDialog(message, opts) {
    opts = opts || {};
    ensureConfirmDialog();
    document.getElementById('confirm-dialog-message').textContent = message;
    var okBtn = confirmDialogEl.querySelector('[data-confirm-ok]');
    okBtn.textContent = opts.confirmText || 'Confirm';
    okBtn.className = 'btn ' + (opts.danger ? 'btn-danger' : 'btn-primary');
    confirmDialogEl.style.display = 'flex';
    confirmDialogEl.setAttribute('aria-hidden', 'false');
    confirmDialogLastFocus = document.activeElement;
    // Focus Cancel first so a stray Enter does not confirm a destructive
    // action; Tab reaches Confirm.
    confirmDialogEl.querySelector('[data-confirm-cancel]').focus();
    return new Promise(function(resolve) { confirmDialogResolve = resolve; });
}

function closeConfirmDialog(ok) {
    if (!confirmDialogEl) return;
    confirmDialogEl.style.display = 'none';
    confirmDialogEl.setAttribute('aria-hidden', 'true');
    var resolve = confirmDialogResolve;
    confirmDialogResolve = null;
    if (resolve) resolve(ok);
    if (confirmDialogLastFocus && typeof confirmDialogLastFocus.focus === 'function') {
        confirmDialogLastFocus.focus();
    }
}

function initDelegatedListeners() {
    document.addEventListener('click', function(e) {
        var actionTarget = e.target.closest('[data-action]');
        if (actionTarget) {
            var action = actionTarget.getAttribute('data-action');
            switch (action) {
                case 'toggle-theme':
                    e.preventDefault();
                    toggleTheme();
                    return;
                case 'toggle-sidebar':
                    e.preventDefault();
                    toggleSidebar();
                    return;
                case 'generate-tsig':
                    generateTSIGSecret();
                    return;
                case 'copy-api-key':
                    e.preventDefault();
                    copyAPIKey();
                    return;
                case 'add-record-row':
                    addRecordRow();
                    return;
                case 'edit-record':
                    e.preventDefault();
                    editRecordRow(actionTarget);
                    return;
                case 'save-record':
                    e.preventDefault();
                    saveRecordRow(actionTarget);
                    return;
                case 'cancel-edit':
                    e.preventDefault();
                    cancelEditRow(actionTarget);
                    return;
                case 'bulk-edit-selected':
                    e.preventDefault();
                    bulkEditSelected();
                    return;
            }
            // Bulk-delete buttons dispatch through the factory-built controllers.
            var bulkDelete = bulkDeleteByAction[action];
            if (bulkDelete) {
                e.preventDefault();
                bulkDelete();
                return;
            }
        }

        var confirmForm = e.target.closest('form[data-confirm]');
        var confirmTrigger = e.target.closest('button, input[type=submit]');
        if (confirmForm && confirmTrigger) {
            // The native click would submit the form; stop it unconditionally,
            // show the modal, and submit programmatically only on confirm.
            // HTMLFormElement.submit() bypasses the event dispatch (no re-entry
            // into this click handler) and these simple action forms carry
            // their target id + CSRF as hidden inputs (REVIEW.md L-16d).
            e.preventDefault();
            var message = confirmForm.getAttribute('data-confirm');
            var label = (confirmTrigger.textContent || '').trim() || 'Confirm';
            confirmDialog(message, { danger: true, confirmText: label }).then(function(ok) {
                if (ok) confirmForm.submit();
            });
        }
    });

    document.addEventListener('change', function(e) {
        var actionTarget = e.target.closest('[data-action]');
        if (actionTarget) {
            var action = actionTarget.getAttribute('data-action');
            if (action === 'toggle-template-vars' || action === 'toggle-apply-template-vars') {
                toggleTemplateVars(actionTarget);
                return;
            }
            if (action === 'per-page') {
                applyPerPage(actionTarget);
                return;
            }
            if (action === 'toggle-priority') {
                togglePriority(actionTarget);
                return;
            }
            var selectAll = bulkSelectAllByAction[action];
            if (selectAll) {
                selectAll(actionTarget);
                return;
            }
        }
        // Per-row selection checkbox (no data-action): keep the count and the
        // header "select all" indicator in sync as individual rows toggle.
        if (e.target.classList) {
            for (var ci = 0; ci < e.target.classList.length; ci++) {
                var rowUpdate = bulkUpdateByCheckboxClass[e.target.classList[ci]];
                if (rowUpdate) { rowUpdate(); break; }
            }
        }
    });
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
        initDelegatedListeners();
        initRecordPriority();
        initImportFeedback();
        syncAllBulkCounts();
    });
} else {
    initDelegatedListeners();
    initRecordPriority();
    initImportFeedback();
    syncAllBulkCounts();
}
