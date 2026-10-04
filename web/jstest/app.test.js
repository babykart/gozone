'use strict';

// Unit tests for the browser logic in web/static/js/app.js, run with
// `node --test web/jstest/` (also wired into CI). app.js is a classic
// browser script, not a module, so it is loaded via require() with its
// boot blocks inert (they are guarded on typeof document) and exercised
// against the minimal DOM stubs below — enough surface for the functions
// under test, without a jsdom dependency.
//
// The select-filter coverage is the regression suite for the group-form
// filtering bugs: Enter submitting the enclosing form, a single select
// keeping a hidden option selected, and a multi-select hiding options that
// were still part of the submission.

const test = require('node:test');
const assert = require('node:assert');

const app = require('../static/js/app.js');

// --- Minimal DOM stubs ------------------------------------------------------

// stubOption/stubSelect model just enough of HTMLOptionElement/HTMLSelectElement:
// label text, per-option hidden/selected flags and the selectedIndex field.
function stubOption(label) {
    return { textContent: label, hidden: false, selected: false };
}

function stubSelect(labels, multiple) {
    const options = labels.map(stubOption);
    return {
        multiple: !!multiple,
        options: options,
        selectedIndex: options.length ? 0 : -1
    };
}

// stubFilterInput models the <input data-action="filter-options"
// data-target="…"> element. closest() reports the element itself for the
// data-action probe the delegated listeners perform.
function stubFilterInput(targetId) {
    return {
        value: '',
        attrs: { 'data-action': 'filter-options', 'data-target': targetId },
        getAttribute(name) { return Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name] : null; },
        closest() { return this; }
    };
}

// stubDocument captures addEventListener registrations and maps ids to
// elements, so the delegated keydown/input handlers can be driven with
// synthetic events.
function stubDocument() {
    const listeners = {};
    const elements = {};
    return {
        addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
        getElementById(id) { return elements[id] || null; },
        setElement(id, el) { elements[id] = el; },
        dispatch(type, target) {
            let prevented = false;
            const event = {
                key: type === 'keydown' ? target.key : undefined,
                target: target,
                preventDefault() { prevented = true; }
            };
            for (const fn of listeners[type] || []) fn(event);
            return prevented;
        }
    };
}

// withDocument installs a stub document for the duration of fn and restores
// the previous global afterwards.
function withDocument(doc, fn) {
    const prev = global.document;
    global.document = doc;
    try {
        fn();
    } finally {
        global.document = prev;
    }
}

// --- bulkFailedSuffix ---------------------------------------------------------

test('bulkFailedSuffix formats the failure tail', () => {
    assert.strictEqual(
        app.bulkFailedSuffix(2, ['a.example.com.', 'b.example.com.']),
        '; 2 failed: a.example.com., b.example.com.'
    );
});

// --- filterOptions: single select --------------------------------------------

test('single select moves selection to first visible option when selected is filtered out', () => {
    const doc = stubDocument();
    const select = stubSelect(['alice', 'bob', 'carol']);
    doc.setElement('user_id', select);
    const input = stubFilterInput('user_id');

    withDocument(doc, () => app.filterOptions(input));

    assert.strictEqual(select.selectedIndex, 0, 'initial selection is the first option');
    assert.strictEqual(select.options[0].hidden, false);

    input.value = 'car';
    withDocument(doc, () => app.filterOptions(input));

    assert.strictEqual(select.options[0].hidden, true, 'alice off-filter');
    assert.strictEqual(select.options[1].hidden, true, 'bob off-filter');
    assert.strictEqual(select.options[2].hidden, false, 'carol matches');
    assert.strictEqual(select.selectedIndex, 2, 'selection moves to the first (only) visible option');
});

test('single select clears selection when the filter matches nothing', () => {
    const doc = stubDocument();
    const select = stubSelect(['alice', 'bob']);
    doc.setElement('user_id', select);
    const input = stubFilterInput('user_id');

    input.value = 'zzz';
    withDocument(doc, () => app.filterOptions(input));

    assert.strictEqual(select.options[0].hidden, true);
    assert.strictEqual(select.options[1].hidden, true);
    assert.strictEqual(select.selectedIndex, -1, 'no visible option — selection cleared so Add posts nothing');
});

test('single select keeps a matching selection untouched', () => {
    const doc = stubDocument();
    const select = stubSelect(['alice', 'bob', 'carol']);
    select.selectedIndex = 1; // bob
    doc.setElement('user_id', select);
    const input = stubFilterInput('user_id');

    input.value = 'bob';
    withDocument(doc, () => app.filterOptions(input));

    assert.strictEqual(select.selectedIndex, 1, 'visible selection must not move');
    assert.strictEqual(select.options[1].hidden, false);
});

// --- filterOptions: multi select ----------------------------------------------

test('multi select keeps chosen options visible while filtering', () => {
    const doc = stubDocument();
    const select = stubSelect(['alice', 'bob', 'carol'], true);
    select.options[1].selected = true; // bob chosen by the operator
    doc.setElement('user_ids', select);
    const input = stubFilterInput('user_ids');

    input.value = 'ali';
    withDocument(doc, () => app.filterOptions(input));

    assert.strictEqual(select.options[0].hidden, false, 'alice matches');
    assert.strictEqual(select.options[1].hidden, false, 'bob is selected: pinned visible even off-filter');
    assert.strictEqual(select.options[2].hidden, true, 'carol off-filter and unselected');
});

test('multi select with no selection hides every non-matching option', () => {
    const doc = stubDocument();
    const select = stubSelect(['alice', 'bob'], true);
    doc.setElement('user_ids', select);
    const input = stubFilterInput('user_ids');

    input.value = 'bob';
    withDocument(doc, () => app.filterOptions(input));

    assert.strictEqual(select.options[0].hidden, true);
    assert.strictEqual(select.options[1].hidden, false);
});

test('empty query restores every option and never forces a selection', () => {
    const doc = stubDocument();
    const select = stubSelect(['alice', 'bob', 'carol']);
    select.selectedIndex = 2;
    doc.setElement('user_id', select);
    const input = stubFilterInput('user_id');

    input.value = 'zzz';
    withDocument(doc, () => app.filterOptions(input));
    input.value = '';
    withDocument(doc, () => app.filterOptions(input));

    for (const opt of select.options) {
        assert.strictEqual(opt.hidden, false, 'empty query must unhide every option');
    }
    // The no-match filter cleared the selection; clearing the query restores
    // visibility but must not force a new selection (the adjust block only
    // runs for a non-empty query). The operator re-picks explicitly.
    assert.strictEqual(select.selectedIndex, -1, 'empty query must not force a selection');
});

// --- delegated listeners ------------------------------------------------------

test('Enter in a filter input is swallowed instead of submitting the form', () => {
    const doc = stubDocument();
    const input = stubFilterInput('user_id');

    let prevented = false;
    withDocument(doc, () => {
        app.initDelegatedListeners();
        input.key = 'Enter';
        prevented = doc.dispatch('keydown', input);
    });
    assert.strictEqual(prevented, true, 'Enter on a filter input must call preventDefault (no implicit form submission)');
});

test('other keys and non-filter targets are not intercepted', () => {
    const doc = stubDocument();
    const input = stubFilterInput('user_id');
    const plain = { key: 'Enter', closest() { return null; } }; // no data-action ancestor

    let typingPrevented = false;
    let plainPrevented = false;
    withDocument(doc, () => {
        app.initDelegatedListeners();
        input.key = 'a';
        typingPrevented = doc.dispatch('keydown', input);
        plainPrevented = doc.dispatch('keydown', plain);
    });
    assert.strictEqual(typingPrevented, false, 'plain typing must not be intercepted');
    assert.strictEqual(plainPrevented, false, 'Enter outside a filter input must not be intercepted');
});

test('input event drives filterOptions through the delegated listener', () => {
    const doc = stubDocument();
    const select = stubSelect(['alice', 'bob']);
    doc.setElement('user_id', select);
    const input = stubFilterInput('user_id');
    input.value = 'ali';

    withDocument(doc, () => {
        app.initDelegatedListeners();
        doc.dispatch('input', input);
    });

    assert.strictEqual(select.options[0].hidden, false, 'alice matches the typed text');
    assert.strictEqual(select.options[1].hidden, true, 'bob filtered out via the delegated input handler');
});

// --- Blocked-storage safety (storageGet/storageSet) -------------------------
//
// localStorage can be unavailable or throw on every access (Safari private
// mode, blocked cookies, quota, enterprise policies). The boot block used to
// hit it unguarded, aborting the whole script before the delegated listeners
// were wired — every interaction on the page died with the preference.

test('storageGet returns the stored value when the storage works', () => {
    const store = { 'gozone-sidebar': 'true' };
    const prev = global.localStorage;
    global.localStorage = {
        getItem: (k) => Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null,
        setItem: (k, v) => { store[k] = String(v); }
    };
    try {
        assert.strictEqual(app.storageGet('gozone-sidebar'), 'true');
        assert.strictEqual(app.storageGet('missing'), null);
        app.storageSet('gozone-theme', 'dark');
        assert.strictEqual(store['gozone-theme'], 'dark');
    } finally {
        global.localStorage = prev;
    }
});

test('storageGet/storageSet survive a storage that throws on every access', () => {
    const prev = global.localStorage;
    const boom = () => { throw new Error('SecurityError: storage blocked'); };
    global.localStorage = { getItem: boom, setItem: boom };
    try {
        assert.strictEqual(app.storageGet('gozone-sidebar'), null, 'a blocked read must yield null, not throw');
        assert.doesNotThrow(() => app.storageSet('gozone-theme', 'dark'), 'a blocked write must be swallowed');
    } finally {
        global.localStorage = prev;
    }
});

test('storageGet/storageSet survive localStorage being entirely undefined', () => {
    const prev = global.localStorage;
    delete global.localStorage;
    try {
        assert.strictEqual(app.storageGet('gozone-sidebar'), null);
        assert.doesNotThrow(() => app.storageSet('gozone-sidebar', true));
    } finally {
        global.localStorage = prev;
    }
});

// --- Batch "Clear all comments" flag sync -----------------------------------
//
// The flag is submitted by a per-row hidden input (exactly one 0/1 value per
// row); the checkbox carries no name and only mirrors its state. These tests
// pin the mirror function: a checkbox-named field was sparse (unchecked
// boxes are not submitted) and its indices drifted against the rows, so
// checking row 2 cleared row 1's comments.

function stubCommentClearRow(hiddenValue, checked) {
    const hidden = { name: 'comment_clear', type: 'hidden', value: hiddenValue };
    const row = {
        querySelector(sel) {
            if (sel === 'input[type=hidden][name=comment_clear]') return hidden;
            return null;
        }
    };
    const checkbox = {
        checked: checked,
        closest(sel) { return sel === '.record-row' ? row : null; }
    };
    return { hidden: hidden, checkbox: checkbox };
}

test('syncCommentClearValue writes 1 into the hidden input when checked', () => {
    const ctx = stubCommentClearRow('0', true);
    app.syncCommentClearValue(ctx.checkbox);
    assert.strictEqual(ctx.hidden.value, '1');
});

test('syncCommentClearValue writes 0 into the hidden input when unchecked', () => {
    const ctx = stubCommentClearRow('1', false);
    app.syncCommentClearValue(ctx.checkbox);
    assert.strictEqual(ctx.hidden.value, '0');
});

test('syncCommentClearValue is a no-op outside a record row', () => {
    const orphan = { checked: true, closest() { return null; } };
    app.syncCommentClearValue(orphan); // must not throw
});

// --- Inline edit row resync (saveRecordRow / applyRecordUpdate) -------------
//
// The server normalises record content (FQDN targets dotted, TXT quoted,
// MX/SRV priority embedded then split back out for display). These tests pin
// the resync: after a save, the row attributes (data-original-content,
// data-original-priority, data-disabled), the read-only cells, the status
// badge and the Delete form must all hold the server-normalised values —
// not what the user typed. A desynchronised row made the next inline edit
// append a duplicate record and the Delete form target a stale one.

function stubDeleteForm() {
    const inputs = {
        'content': { name: 'content', value: 'old.target.example.com.' },
        'priority': { name: 'priority', value: '0' }
    };
    return {
        querySelector(sel) {
            const name = sel.replace(/^input\[name=/, '').replace(/\]$/, '');
            return Object.prototype.hasOwnProperty.call(inputs, name) ? inputs[name] : null;
        }
    };
}

function stubInlineRow() {
    const attrs = {
        'data-zone-id': 'example.com',
        'data-csrf': 'csrf-token',
        'data-name': 'www.example.com',
        'data-type': 'CNAME',
        'data-original-content': 'old.target.example.com.',
        'data-original-priority': '0',
        'data-disabled': 'false'
    };
    const els = {
        '.ev-content': { value: 'backup.example.com' },
        '.ev-ttl': { value: '3600' },
        '.ev-prio': { value: '0' },
        '.ev-disabled': { checked: false },
        '.ev-comments': { value: '' },
        '.ev-comment-clear-cb': { checked: false },
        '.rv-content': { textContent: 'old.target.example.com.' },
        '.rv-ttl': { textContent: '300' },
        '.rv-prio': { textContent: '-' },
        '.rv-status': { innerHTML: '<span class="badge badge-active">Active</span>' },
        '.rv-comments': null,
        'form.record-delete': stubDeleteForm()
    };
    return {
        attrs: attrs,
        els: els,
        deleteForm: els['form.record-delete'],
        getAttribute(name) { return Object.prototype.hasOwnProperty.call(attrs, name) ? attrs[name] : null; },
        setAttribute(name, value) { attrs[name] = String(value); },
        querySelector(sel) { return Object.prototype.hasOwnProperty.call(els, sel) ? els[sel] : null; },
        querySelectorAll() { return []; }
    };
}

test('applyRecordUpdate resyncs the row from the server-normalised record', () => {
    const row = stubInlineRow();
    app.applyRecordUpdate(row, { content: 'backup.example.com.', priority: 0, disabled: false }, 3600);

    assert.strictEqual(row.attrs['data-original-content'], 'backup.example.com.', 'original-content must hold the normalised content for the next edit');
    assert.strictEqual(row.attrs['data-original-priority'], '0');
    assert.strictEqual(row.attrs['data-disabled'], 'false');
    assert.strictEqual(row.els['.rv-content'].textContent, 'backup.example.com.');
    assert.strictEqual(row.els['.rv-ttl'].textContent, 3600, 'TTL cell follows the saved RRSet');
    assert.strictEqual(row.els['.rv-prio'].textContent, '-');
    assert.strictEqual(row.els['.ev-content'].value, 'backup.example.com.', 'edit textarea stays aligned with the stored value');
    assert.strictEqual(row.deleteForm.querySelector('input[name=content]').value, 'backup.example.com.', 'Delete form content follows the saved record');
});

test('applyRecordUpdate updates the Delete form target', () => {
    const row = stubInlineRow();
    app.applyRecordUpdate(row, { content: 'backup.example.com.', priority: 20, disabled: true }, 60);

    const content = row.deleteForm.querySelector('input[name=content]');
    const prio = row.deleteForm.querySelector('input[name=priority]');
    assert.strictEqual(content.value, 'backup.example.com.', 'Delete must submit the post-edit content');
    assert.strictEqual(prio.value, '20', 'Delete must submit the post-edit priority');
});

test('applyRecordUpdate reads the badge from the saved record, not records[0]', () => {
    const row = stubInlineRow();
    // disabled flag lives on the updated record; a records[0]-based badge
    // shows the wrong status on a multi-record RRSet.
    app.applyRecordUpdate(row, { content: 'x.example.com.', priority: 0, disabled: true }, 3600);
    assert.strictEqual(row.attrs['data-disabled'], 'true');
    assert.ok(row.els['.rv-status'].innerHTML.indexOf('badge-disabled') !== -1, 'badge must reflect the saved record');

    app.applyRecordUpdate(row, { content: 'x.example.com.', priority: 0, disabled: false }, 3600);
    assert.ok(row.els['.rv-status'].innerHTML.indexOf('badge-active') !== -1);
});

test('applyRecordUpdate displays a positive priority and dashes zero', () => {
    const row = stubInlineRow();
    app.applyRecordUpdate(row, { content: 'backup.example.com.', priority: 10, disabled: false }, 3600);
    assert.strictEqual(row.els['.rv-prio'].textContent, '10');
    assert.strictEqual(row.els['.ev-prio'].value, '10');

    app.applyRecordUpdate(row, { content: 'a.example.com.', priority: 0, disabled: false }, 3600);
    assert.strictEqual(row.els['.rv-prio'].textContent, '-');
});

test('saveRecordRow posts the row identity and resyncs from the response', async () => {
    const row = stubInlineRow();
    const btn = { closest(sel) { return sel === 'tr' ? row : null; } };

    const payload = {
        success: true,
        record: {
            name: 'www.example.com', type: 'MX', ttl: 3600,
            records: [{ content: '20 backup.example.com.', priority: 0, disabled: false }]
        },
        updated: { content: 'backup.example.com.', priority: 20, disabled: true }
    };
    const doc = stubDocument();
    doc.setElement('notification', { textContent: '', className: '', style: {} });
    const prevDocument = global.document;
    const prevFetch = global.fetch;
    const calls = [];

    global.fetch = function(url, opts) {
        calls.push({ url: url, body: opts.body });
        return Promise.resolve({
            ok: true,
            redirected: false,
            headers: { get: function() { return 'application/json'; } },
            json: function() { return Promise.resolve(payload); }
        });
    };
    global.document = doc;

    try {
        app.saveRecordRow(btn);
        await new Promise(function(res) { setTimeout(res, 10); });
    } finally {
        global.fetch = prevFetch;
        global.document = prevDocument;
    }

    assert.strictEqual(calls.length, 1);
    assert.strictEqual(calls[0].url, '/zones/example.com/records/inline-update');
    const body = calls[0].body;
    assert.ok(body.indexOf('original_content=old.target.example.com.') !== -1, 'request carries the pre-edit content');
    assert.ok(body.indexOf('original_priority=0') !== -1);
    assert.ok(body.indexOf('content=backup.example.com') !== -1);

    // Row now holds the server-normalised identity.
    assert.strictEqual(row.attrs['data-original-content'], 'backup.example.com.');
    assert.strictEqual(row.attrs['data-original-priority'], '20');
    assert.strictEqual(row.attrs['data-disabled'], 'true');
    assert.strictEqual(row.els['.rv-ttl'].textContent, 3600);
    assert.ok(row.els['.rv-status'].innerHTML.indexOf('badge-disabled') !== -1, 'badge from updated.disabled, not records[0].disabled');
    assert.strictEqual(row.deleteForm.querySelector('input[name=content]').value, 'backup.example.com.');
});
