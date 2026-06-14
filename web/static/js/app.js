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
    for (var i = 0; i < displayEls.length; i++) displayEls[i].style.display = editing ? 'none' : '';
    for (var j = 0; j < editEls.length; j++) editEls[j].style.display = editing ? '' : 'none';
}

function resetRowValues(row) {
    var editContent = row.querySelector('.ev-content');
    var editTTL = row.querySelector('.ev-ttl');
    var editPrio = row.querySelector('.ev-prio');
    var editDisabled = row.querySelector('.ev-disabled');

    var origContent = row.querySelector('.rv-content');
    var origTTL = row.querySelector('.rv-ttl');
    var origPrio = row.querySelector('.rv-prio');

    if (editContent && origContent) editContent.value = origContent.textContent;
    if (editTTL && origTTL) editTTL.value = origTTL.textContent;
    if (editPrio && origPrio) editPrio.value = (origPrio.textContent === '-' ? '0' : origPrio.textContent);
    if (editDisabled) editDisabled.checked = row.getAttribute('data-disabled') === 'true';
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
    var select = template.querySelector('select[name=type]');
    if (select) select.value = select.querySelector('option').value;
    var prioGrp = template.querySelector('.record-prio-group');
    if (prioGrp) prioGrp.style.display = 'none';
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
    var searchInput = document.querySelector('input[name=search]');
    var q = '?' + prefix + 'PerPage=' + select.value;
    if (searchInput && searchInput.value) {
        q += '&search=' + encodeURIComponent(searchInput.value);
    }
    window.location.href = q;
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
            }
        }

        var confirmForm = e.target.closest('form[data-confirm]');
        var confirmTrigger = e.target.closest('button, input[type=submit]');
        if (confirmForm && confirmTrigger) {
            var message = confirmForm.getAttribute('data-confirm');
            if (!confirm(message)) {
                e.preventDefault();
            }
        }
    });

    document.addEventListener('change', function(e) {
        var actionTarget = e.target.closest('[data-action]');
        if (!actionTarget) return;
        var action = actionTarget.getAttribute('data-action');
        if (action === 'toggle-template-vars' || action === 'toggle-apply-template-vars') {
            toggleTemplateVars(actionTarget);
        } else if (action === 'per-page') {
            applyPerPage(actionTarget);
        }
    });
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initDelegatedListeners);
} else {
    initDelegatedListeners();
}
