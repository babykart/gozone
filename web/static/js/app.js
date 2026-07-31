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
    var theme = localStorage.getItem('gozone-theme') || 'light';
    document.documentElement.setAttribute('data-theme', theme);

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

// --- Bulk record selection ---
//
// The zone records table exposes per-row checkboxes plus a "select all"
// checkbox in the header and a bulk-action toolbar. "Edit selected" flips every
// checked row into inline edit mode (each row is then saved individually via the
// existing inline-update flow); "Delete selected" POSTs the selection to the
// bulk-delete endpoint and reloads the page on success.

function selectedRecordRows() {
    var boxes = document.querySelectorAll('.record-select');
    var rows = [];
    for (var i = 0; i < boxes.length; i++) {
        if (boxes[i].checked) rows.push(boxes[i].closest('tr'));
    }
    return rows;
}

function updateBulkSelectedCount() {
    var rows = selectedRecordRows();
    var countEl = document.getElementById('bulk-selected-count');
    if (countEl) {
        countEl.textContent = rows.length + (rows.length === 1 ? ' record selected' : ' records selected');
    }
    var selectAll = document.querySelector('[data-action="select-all-records"]');
    var boxes = document.querySelectorAll('.record-select');
    if (selectAll) {
        var allChecked = boxes.length > 0;
        for (var i = 0; i < boxes.length; i++) {
            if (!boxes[i].checked) { allChecked = false; break; }
        }
        selectAll.checked = allChecked;
    }
}

function toggleSelectAllRecords(cb) {
    var boxes = document.querySelectorAll('.record-select');
    for (var i = 0; i < boxes.length; i++) boxes[i].checked = cb.checked;
    updateBulkSelectedCount();
}

function bulkEditSelected() {
    var rows = selectedRecordRows();
    if (rows.length === 0) { showNotification('Select at least one record first', 'warning'); return; }
    for (var i = 0; i < rows.length; i++) toggleEditMode(rows[i], true);
    showNotification(rows.length + (rows.length === 1 ? ' record' : ' records') + ' in edit mode', 'success');
}

async function bulkDeleteSelected() {
    var rows = selectedRecordRows();
    if (rows.length === 0) { showNotification('Select at least one record first', 'warning'); return; }
    if (!await confirmDialog('Delete ' + rows.length + ' selected record(s)? This cannot be undone.', { danger: true, confirmText: 'Delete' })) return;

    var bar = document.getElementById('bulk-actions-bar');
    var zoneID = bar ? bar.getAttribute('data-zone-id') : '';
    var csrfToken = bar ? bar.getAttribute('data-csrf') : '';

    var formData = new URLSearchParams();
    if (csrfToken) formData.append('gorilla.csrf.Token', csrfToken);
    for (var i = 0; i < rows.length; i++) {
        formData.append('name', rows[i].getAttribute('data-name'));
        formData.append('type', rows[i].getAttribute('data-type'));
        formData.append('original_content', rows[i].getAttribute('data-original-content'));
        formData.append('original_priority', rows[i].getAttribute('data-original-priority'));
    }

    fetch('/zones/' + zoneID + '/records/bulk-delete', {
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
        showNotification('Deleted ' + data.deleted + ' record(s)', 'success');
        window.location.reload();
    })
    .catch(function(err) {
        showNotification('Delete failed: ' + err.message, 'error');
    });
}

// --- Bulk zone selection ---
//
// The zones list (admin only) exposes per-row checkboxes, a "select all"
// checkbox in the header, and a "Delete selected" toolbar button that POSTs
// the selection to /zones/bulk-delete (best-effort) and reloads on success.

function selectedZoneRows() {
    var boxes = document.querySelectorAll('.zone-select');
    var rows = [];
    for (var i = 0; i < boxes.length; i++) {
        if (boxes[i].checked) rows.push(boxes[i].closest('tr'));
    }
    return rows;
}

function updateBulkZonesCount() {
    var rows = selectedZoneRows();
    var countEl = document.getElementById('bulk-zones-count');
    if (countEl) {
        countEl.textContent = rows.length + (rows.length === 1 ? ' zone selected' : ' zones selected');
    }
    var selectAll = document.querySelector('[data-action="select-all-zones"]');
    var boxes = document.querySelectorAll('.zone-select');
    if (selectAll) {
        var allChecked = boxes.length > 0;
        for (var i = 0; i < boxes.length; i++) {
            if (!boxes[i].checked) { allChecked = false; break; }
        }
        selectAll.checked = allChecked;
    }
}

function toggleSelectAllZones(cb) {
    var boxes = document.querySelectorAll('.zone-select');
    for (var i = 0; i < boxes.length; i++) boxes[i].checked = cb.checked;
    updateBulkZonesCount();
}

async function bulkDeleteZones() {
    var rows = selectedZoneRows();
    if (rows.length === 0) { showNotification('Select at least one zone first', 'warning'); return; }
    if (!await confirmDialog('Delete ' + rows.length + ' selected zone(s)? This cannot be undone.', { danger: true, confirmText: 'Delete' })) return;

    var bar = document.getElementById('bulk-zones-bar');
    var csrfToken = bar ? bar.getAttribute('data-csrf') : '';

    var formData = new URLSearchParams();
    if (csrfToken) formData.append('gorilla.csrf.Token', csrfToken);
    for (var i = 0; i < rows.length; i++) {
        formData.append('zone_id', rows[i].getAttribute('data-zone-id'));
    }

    fetch('/zones/bulk-delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
    })
    .then(function(resp) {
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
        var msg = 'Deleted ' + data.deleted + ' zone(s)';
        if (data.failed && data.failed.length > 0) {
            msg += '; ' + data.failed.length + ' failed: ' + data.failed.join(', ');
        }
        showNotification(msg, data.failed && data.failed.length > 0 ? 'warning' : 'success');
        window.location.reload();
    })
    .catch(function(err) {
        showNotification('Delete failed: ' + err.message, 'error');
    });
}

// --- Bulk TSIG key selection ---
//
// The TSIG keys list exposes per-row checkboxes, a "select all" checkbox in
// the header, and a "Delete selected" toolbar button that POSTs the selection
// to /tsigkeys/bulk-delete (best-effort) and reloads on success.

function selectedTSIGRows() {
    var boxes = document.querySelectorAll('.tsig-select');
    var rows = [];
    for (var i = 0; i < boxes.length; i++) {
        if (boxes[i].checked) rows.push(boxes[i].closest('tr'));
    }
    return rows;
}

function updateBulkTSIGCount() {
    var rows = selectedTSIGRows();
    var countEl = document.getElementById('bulk-tsig-count');
    if (countEl) {
        countEl.textContent = rows.length + (rows.length === 1 ? ' key selected' : ' keys selected');
    }
    var selectAll = document.querySelector('[data-action="select-all-tsig"]');
    var boxes = document.querySelectorAll('.tsig-select');
    if (selectAll) {
        var allChecked = boxes.length > 0;
        for (var i = 0; i < boxes.length; i++) {
            if (!boxes[i].checked) { allChecked = false; break; }
        }
        selectAll.checked = allChecked;
    }
}

function toggleSelectAllTSIG(cb) {
    var boxes = document.querySelectorAll('.tsig-select');
    for (var i = 0; i < boxes.length; i++) boxes[i].checked = cb.checked;
    updateBulkTSIGCount();
}

async function bulkDeleteTSIG() {
    var rows = selectedTSIGRows();
    if (rows.length === 0) { showNotification('Select at least one key first', 'warning'); return; }
    if (!await confirmDialog('Delete ' + rows.length + ' selected TSIG key(s)? This cannot be undone.', { danger: true, confirmText: 'Delete' })) return;

    var bar = document.getElementById('bulk-tsig-bar');
    var csrfToken = bar ? bar.getAttribute('data-csrf') : '';

    var formData = new URLSearchParams();
    if (csrfToken) formData.append('gorilla.csrf.Token', csrfToken);
    for (var i = 0; i < rows.length; i++) {
        formData.append('key_id', rows[i].getAttribute('data-key-id'));
    }

    fetch('/tsigkeys/bulk-delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
    })
    .then(function(resp) {
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
        var msg = 'Deleted ' + data.deleted + ' key(s)';
        if (data.failed && data.failed.length > 0) {
            msg += '; ' + data.failed.length + ' failed: ' + data.failed.join(', ');
        }
        showNotification(msg, data.failed && data.failed.length > 0 ? 'warning' : 'success');
        window.location.reload();
    })
    .catch(function(err) {
        showNotification('Delete failed: ' + err.message, 'error');
    });
}

// --- Bulk API key selection ---
//
// The "Your API Keys" list exposes per-row checkboxes, a "select all" header
// checkbox, and a "Delete selected" toolbar button that POSTs the selection to
// /profile/api-keys/bulk-delete (ownership-enforced server-side) and reloads on
// success.

function selectedAPIKeyRows() {
    var boxes = document.querySelectorAll('.apikey-select');
    var rows = [];
    for (var i = 0; i < boxes.length; i++) {
        if (boxes[i].checked) rows.push(boxes[i].closest('tr'));
    }
    return rows;
}

function updateBulkAPIKeyCount() {
    var rows = selectedAPIKeyRows();
    var countEl = document.getElementById('bulk-apikey-count');
    if (countEl) {
        countEl.textContent = rows.length + (rows.length === 1 ? ' key selected' : ' keys selected');
    }
    var selectAll = document.querySelector('[data-action="select-all-apikeys"]');
    var boxes = document.querySelectorAll('.apikey-select');
    if (selectAll) {
        var allChecked = boxes.length > 0;
        for (var i = 0; i < boxes.length; i++) {
            if (!boxes[i].checked) { allChecked = false; break; }
        }
        selectAll.checked = allChecked;
    }
}

function toggleSelectAllAPIKeys(cb) {
    var boxes = document.querySelectorAll('.apikey-select');
    for (var i = 0; i < boxes.length; i++) boxes[i].checked = cb.checked;
    updateBulkAPIKeyCount();
}

async function bulkDeleteAPIKeys() {
    var rows = selectedAPIKeyRows();
    if (rows.length === 0) { showNotification('Select at least one key first', 'warning'); return; }
    if (!await confirmDialog('Delete ' + rows.length + ' selected API key(s)? This cannot be undone.', { danger: true, confirmText: 'Delete' })) return;

    var bar = document.getElementById('bulk-apikey-bar');
    var csrfToken = bar ? bar.getAttribute('data-csrf') : '';

    var formData = new URLSearchParams();
    if (csrfToken) formData.append('gorilla.csrf.Token', csrfToken);
    for (var i = 0; i < rows.length; i++) {
        formData.append('key_id', rows[i].getAttribute('data-key-id'));
    }

    fetch('/profile/api-keys/bulk-delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
    })
    .then(function(resp) {
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
        var msg = 'Deleted ' + data.deleted + ' key(s)';
        if (data.failed && data.failed.length > 0) {
            msg += '; ' + data.failed.length + ' failed: ' + data.failed.join(', ');
        }
        showNotification(msg, data.failed && data.failed.length > 0 ? 'warning' : 'success');
        window.location.reload();
    })
    .catch(function(err) {
        showNotification('Delete failed: ' + err.message, 'error');
    });
}

// --- Bulk user selection ---
//
// The users list (admin only) exposes per-row checkboxes (never for the admin's
// own row), a "select all" header checkbox, and a "Delete selected" toolbar
// button that POSTs the selection to /users/bulk-delete (server enforces
// self-delete and last-admin guards) and reloads on success.

function selectedUserRows() {
    var boxes = document.querySelectorAll('.user-select');
    var rows = [];
    for (var i = 0; i < boxes.length; i++) {
        if (boxes[i].checked) rows.push(boxes[i].closest('tr'));
    }
    return rows;
}

function updateBulkUsersCount() {
    var rows = selectedUserRows();
    var countEl = document.getElementById('bulk-users-count');
    if (countEl) {
        countEl.textContent = rows.length + (rows.length === 1 ? ' user selected' : ' users selected');
    }
    var selectAll = document.querySelector('[data-action="select-all-users"]');
    var boxes = document.querySelectorAll('.user-select');
    if (selectAll) {
        var allChecked = boxes.length > 0;
        for (var i = 0; i < boxes.length; i++) {
            if (!boxes[i].checked) { allChecked = false; break; }
        }
        selectAll.checked = allChecked;
    }
}

function toggleSelectAllUsers(cb) {
    var boxes = document.querySelectorAll('.user-select');
    for (var i = 0; i < boxes.length; i++) boxes[i].checked = cb.checked;
    updateBulkUsersCount();
}

async function bulkDeleteUsers() {
    var rows = selectedUserRows();
    if (rows.length === 0) { showNotification('Select at least one user first', 'warning'); return; }
    if (!await confirmDialog('Delete ' + rows.length + ' selected user(s)? This cannot be undone.', { danger: true, confirmText: 'Delete' })) return;

    var bar = document.getElementById('bulk-users-bar');
    var csrfToken = bar ? bar.getAttribute('data-csrf') : '';

    var formData = new URLSearchParams();
    if (csrfToken) formData.append('gorilla.csrf.Token', csrfToken);
    for (var i = 0; i < rows.length; i++) {
        formData.append('user_id', rows[i].getAttribute('data-user-id'));
    }

    fetch('/users/bulk-delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
    })
    .then(function(resp) {
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
        var msg = 'Deleted ' + data.deleted + ' user(s)';
        if (data.failed && data.failed.length > 0) {
            msg += '; ' + data.failed.length + ' skipped (self/last-admin): ' + data.failed.join(', ');
        }
        showNotification(msg, data.failed && data.failed.length > 0 ? 'warning' : 'success');
        window.location.reload();
    })
    .catch(function(err) {
        showNotification('Delete failed: ' + err.message, 'error');
    });
}

// --- Bulk group selection ---
//
// The zone groups list exposes per-row checkboxes, a "select all" header
// checkbox, and a "Delete selected" toolbar button that POSTs the selection to
// /groups/bulk-delete (best-effort) and reloads on success.

function selectedGroupRows() {
    var boxes = document.querySelectorAll('.group-select');
    var rows = [];
    for (var i = 0; i < boxes.length; i++) {
        if (boxes[i].checked) rows.push(boxes[i].closest('tr'));
    }
    return rows;
}

function updateBulkGroupsCount() {
    var rows = selectedGroupRows();
    var countEl = document.getElementById('bulk-groups-count');
    if (countEl) {
        countEl.textContent = rows.length + (rows.length === 1 ? ' group selected' : ' groups selected');
    }
    var selectAll = document.querySelector('[data-action="select-all-groups"]');
    var boxes = document.querySelectorAll('.group-select');
    if (selectAll) {
        var allChecked = boxes.length > 0;
        for (var i = 0; i < boxes.length; i++) {
            if (!boxes[i].checked) { allChecked = false; break; }
        }
        selectAll.checked = allChecked;
    }
}

function toggleSelectAllGroups(cb) {
    var boxes = document.querySelectorAll('.group-select');
    for (var i = 0; i < boxes.length; i++) boxes[i].checked = cb.checked;
    updateBulkGroupsCount();
}

async function bulkDeleteGroups() {
    var rows = selectedGroupRows();
    if (rows.length === 0) { showNotification('Select at least one group first', 'warning'); return; }
    if (!await confirmDialog('Delete ' + rows.length + ' selected group(s)? This cannot be undone.', { danger: true, confirmText: 'Delete' })) return;

    var bar = document.getElementById('bulk-groups-bar');
    var csrfToken = bar ? bar.getAttribute('data-csrf') : '';

    var formData = new URLSearchParams();
    if (csrfToken) formData.append('gorilla.csrf.Token', csrfToken);
    for (var i = 0; i < rows.length; i++) {
        formData.append('group_id', rows[i].getAttribute('data-group-id'));
    }

    fetch('/groups/bulk-delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
    })
    .then(function(resp) {
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
        var msg = 'Deleted ' + data.deleted + ' group(s)';
        if (data.failed && data.failed.length > 0) {
            msg += '; ' + data.failed.length + ' failed: ' + data.failed.join(', ');
        }
        showNotification(msg, data.failed && data.failed.length > 0 ? 'warning' : 'success');
        window.location.reload();
    })
    .catch(function(err) {
        showNotification('Delete failed: ' + err.message, 'error');
    });
}

// --- Bulk template selection ---
//
// The templates list exposes per-row checkboxes (never for built-in templates,
// which cannot be deleted), a "select all" header checkbox, and a "Delete
// selected" toolbar button that POSTs the selection to /templates/bulk-delete
// (server still rejects built-ins) and reloads on success.

function selectedTemplateRows() {
    var boxes = document.querySelectorAll('.template-select');
    var rows = [];
    for (var i = 0; i < boxes.length; i++) {
        if (boxes[i].checked) rows.push(boxes[i].closest('tr'));
    }
    return rows;
}

function updateBulkTemplatesCount() {
    var rows = selectedTemplateRows();
    var countEl = document.getElementById('bulk-templates-count');
    if (countEl) {
        countEl.textContent = rows.length + (rows.length === 1 ? ' template selected' : ' templates selected');
    }
    var selectAll = document.querySelector('[data-action="select-all-templates"]');
    var boxes = document.querySelectorAll('.template-select');
    if (selectAll) {
        var allChecked = boxes.length > 0;
        for (var i = 0; i < boxes.length; i++) {
            if (!boxes[i].checked) { allChecked = false; break; }
        }
        selectAll.checked = allChecked;
    }
}

function toggleSelectAllTemplates(cb) {
    var boxes = document.querySelectorAll('.template-select');
    for (var i = 0; i < boxes.length; i++) boxes[i].checked = cb.checked;
    updateBulkTemplatesCount();
}

async function bulkDeleteTemplates() {
    var rows = selectedTemplateRows();
    if (rows.length === 0) { showNotification('Select at least one template first', 'warning'); return; }
    if (!await confirmDialog('Delete ' + rows.length + ' selected template(s)? This cannot be undone.', { danger: true, confirmText: 'Delete' })) return;

    var bar = document.getElementById('bulk-templates-bar');
    var csrfToken = bar ? bar.getAttribute('data-csrf') : '';

    var formData = new URLSearchParams();
    if (csrfToken) formData.append('gorilla.csrf.Token', csrfToken);
    for (var i = 0; i < rows.length; i++) {
        formData.append('template_id', rows[i].getAttribute('data-template-id'));
    }

    fetch('/templates/bulk-delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
    })
    .then(function(resp) {
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
        var msg = 'Deleted ' + data.deleted + ' template(s)';
        if (data.failed && data.failed.length > 0) {
            msg += '; ' + data.failed.length + ' failed (built-in/missing): ' + data.failed.join(', ');
        }
        showNotification(msg, data.failed && data.failed.length > 0 ? 'warning' : 'success');
        window.location.reload();
    })
    .catch(function(err) {
        showNotification('Delete failed: ' + err.message, 'error');
    });
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
                case 'bulk-delete-selected':
                    e.preventDefault();
                    bulkDeleteSelected();
                    return;
                case 'bulk-delete-zones':
                    e.preventDefault();
                    bulkDeleteZones();
                    return;
                case 'bulk-delete-tsig':
                    e.preventDefault();
                    bulkDeleteTSIG();
                    return;
                case 'bulk-delete-apikeys':
                    e.preventDefault();
                    bulkDeleteAPIKeys();
                    return;
                case 'bulk-delete-users':
                    e.preventDefault();
                    bulkDeleteUsers();
                    return;
                case 'bulk-delete-groups':
                    e.preventDefault();
                    bulkDeleteGroups();
                    return;
                case 'bulk-delete-templates':
                    e.preventDefault();
                    bulkDeleteTemplates();
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
            if (action === 'select-all-records') {
                toggleSelectAllRecords(actionTarget);
                return;
            }
            if (action === 'select-all-zones') {
                toggleSelectAllZones(actionTarget);
                return;
            }
            if (action === 'select-all-tsig') {
                toggleSelectAllTSIG(actionTarget);
                return;
            }
            if (action === 'select-all-apikeys') {
                toggleSelectAllAPIKeys(actionTarget);
                return;
            }
            if (action === 'select-all-users') {
                toggleSelectAllUsers(actionTarget);
                return;
            }
            if (action === 'select-all-groups') {
                toggleSelectAllGroups(actionTarget);
                return;
            }
            if (action === 'select-all-templates') {
                toggleSelectAllTemplates(actionTarget);
                return;
            }
        }
        // Per-row selection checkbox (no data-action): keep the count and the
        // header "select all" indicator in sync as individual rows toggle.
        if (e.target.classList && e.target.classList.contains('record-select')) {
            updateBulkSelectedCount();
        }
        if (e.target.classList && e.target.classList.contains('zone-select')) {
            updateBulkZonesCount();
        }
        if (e.target.classList && e.target.classList.contains('tsig-select')) {
            updateBulkTSIGCount();
        }
        if (e.target.classList && e.target.classList.contains('apikey-select')) {
            updateBulkAPIKeyCount();
        }
        if (e.target.classList && e.target.classList.contains('user-select')) {
            updateBulkUsersCount();
        }
        if (e.target.classList && e.target.classList.contains('group-select')) {
            updateBulkGroupsCount();
        }
        if (e.target.classList && e.target.classList.contains('template-select')) {
            updateBulkTemplatesCount();
        }
    });
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
        initDelegatedListeners();
        initRecordPriority();
        initImportFeedback();
        updateBulkSelectedCount();
        updateBulkZonesCount();
        updateBulkTSIGCount();
        updateBulkAPIKeyCount();
        updateBulkUsersCount();
        updateBulkGroupsCount();
        updateBulkTemplatesCount();
    });
} else {
    initDelegatedListeners();
    initRecordPriority();
    initImportFeedback();
    updateBulkSelectedCount();
    updateBulkZonesCount();
    updateBulkTSIGCount();
    updateBulkAPIKeyCount();
    updateBulkUsersCount();
    updateBulkGroupsCount();
    updateBulkTemplatesCount();
}
