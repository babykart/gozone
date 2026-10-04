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

// withClassList attaches a minimal classList implementation to a stub element,
// backed by its className string (like the browser's live classList).
function withClassList(el) {
    var classes = function() {
        return (el.className || '').split(/\s+/).filter(Boolean);
    };
    el.classList = {
        add: function() {
            var set = new Set(classes());
            for (var i = 0; i < arguments.length; i++) set.add(arguments[i]);
            el.className = Array.from(set).join(' ');
        },
        remove: function() {
            var drop = new Set(arguments);
            el.className = classes().filter(function(c) { return !drop.has(c); }).join(' ');
        },
        toggle: function(name, force) {
            var has = classes().indexOf(name) !== -1;
            var want = force === undefined ? !has : !!force;
            if (want && !has) el.classList.add(name);
            if (!want && has) el.classList.remove(name);
            return want;
        },
        contains: function(name) { return classes().indexOf(name) !== -1; }
    };
    return el;
}

// --- Notifications (showNotification) ----------------------------------------
//
// A notification shown within 5 seconds of the previous one used to be hidden
// early by the earlier timer, and visibility was driven by inline
// style.display (against the classList convention, and hiding the aria-live
// region from screen readers).

test('showNotification cancels the previous timer and toggles .hidden', () => {
    const el = withClassList({ textContent: '', className: 'notification hidden' });
    const doc = stubDocument();
    doc.setElement('notification', el);

    const timeouts = [];
    const clears = [];
    const prevSet = global.setTimeout;
    const prevClear = global.clearTimeout;
    global.setTimeout = (fn) => { timeouts.push(fn); return timeouts.length; };
    global.clearTimeout = (id) => { clears.push(id); };
    try {
        withDocument(doc, () => {
            app.showNotification('first', 'error');
            app.showNotification('second', 'success');
        });
    } finally {
        global.setTimeout = prevSet;
        global.clearTimeout = prevClear;
    }

    assert.strictEqual(timeouts.length, 2, 'each notification schedules one hide timer');
    assert.deepStrictEqual(clears, [1], 'the first timer must be cancelled when a second notification arrives');
    assert.strictEqual(el.textContent, 'second');
    assert.ok(!el.classList.contains('hidden'), 'visible via .hidden removal, not inline style');
    assert.ok(el.classList.contains('notification-success'), 'type modifier applied');
    assert.ok(!el.classList.contains('notification-error'), 'previous type modifier dropped');

    // Fire the pending timer: hides via .hidden and clears the text.
    timeouts[1]();
    assert.ok(el.classList.contains('hidden'));
    assert.strictEqual(el.textContent, '');
});

// --- TSIG Generate (generateTSIGSecret) --------------------------------------
//
// The Generate button used to force-select hmac-sha512, silently reverting an
// operator's deliberate algorithm choice. It must respect the selection (and
// size the key to it), only defaulting when the placeholder is still chosen.

function stubTsigPage(algorithmValue) {
    const algo = { value: algorithmValue };
    const key = { value: '' };
    const doc = {
        getElementById(id) {
            if (id === 'algorithm') return algo;
            if (id === 'key') return key;
            return null;
        }
    };
    return { algo: algo, key: key, doc: doc };
}

function withDocumentRun(doc, fn) {
    const prev = global.document;
    global.document = doc;
    try {
        fn();
    } finally {
        global.document = prev;
    }
}

test('generateTSIGSecret keeps the operator-selected algorithm', () => {
    const page = stubTsigPage('hmac-sha256');
    withDocumentRun(page.doc, () => app.generateTSIGSecret());
    assert.strictEqual(page.algo.value, 'hmac-sha256', 'a chosen algorithm must not be overwritten');
    // 32 raw bytes -> 44 base64 chars (with padding).
    assert.strictEqual(page.key.value.length, 44, 'key material must be sized to hmac-sha256 (32 bytes)');
});

test('generateTSIGSecret defaults the algorithm only from the placeholder', () => {
    const page = stubTsigPage('');
    withDocumentRun(page.doc, () => app.generateTSIGSecret());
    assert.strictEqual(page.algo.value, 'hmac-sha512', 'no explicit choice -> default hmac-sha512');
    // 64 raw bytes -> 88 base64 chars.
    assert.strictEqual(page.key.value.length, 88, 'default key material must be sized to hmac-sha512 (64 bytes)');
});

test('generateTSIGSecret sizes the material per algorithm', () => {
    const cases = [
        ['hmac-md5', 16, 24],
        ['hmac-sha256', 32, 44],
        ['hmac-sha384', 48, 64],
        ['hmac-sha512', 64, 88]
    ];
    for (const [algo, raw, b64] of cases) {
        const page = stubTsigPage(algo);
        withDocumentRun(page.doc, () => app.generateTSIGSecret());
        assert.strictEqual(page.key.value.length, b64, `${algo}: expected ${raw} bytes (${b64} base64 chars), got ${page.key.value.length}`);
        assert.strictEqual(page.algo.value, algo);
    }
});

// --- copyAPIKey rejection handling -------------------------------------------
//
// The clipboard write can be denied (permission policy, document not
// focused): the rejected promise used to die as an unhandled rejection; the
// user now gets an actionable notification instead.

test('copyAPIKey surfaces a denied clipboard write instead of an unhandled rejection', async () => {
    const reveal = {
        attrs: { 'data-key': 'gozone_secret' },
        getAttribute(name) { return Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name] : null; },
        querySelector() { return null; } // no .btn inside for updateCopyButton
    };

    const notificationEl = withClassList({ textContent: '', className: 'notification hidden' });
    const doc = stubDocument();
    doc.setElement('notification', notificationEl);
    doc.querySelector = (sel) => (sel === '.api-key-reveal' ? reveal : null);

    const prevDocument = global.document;
    const prevWindow = global.window;
    const navigatorDescriptor = Object.getOwnPropertyDescriptor(global, 'navigator');
    const prevSetTimeout = global.setTimeout;
    global.document = doc;
    global.window = { isSecureContext: true };
    Object.defineProperty(global, 'navigator', {
        value: { clipboard: { writeText: () => Promise.reject(new Error('not allowed')) } },
        configurable: true,
        writable: true
    });
    global.setTimeout = () => 1; // never fire the notification auto-hide

    try {
        await app.copyAPIKey();
        // Let the rejection propagate to the .catch.
        await new Promise((res) => prevSetTimeout(res, 10));
    } finally {
        global.document = prevDocument;
        global.window = prevWindow;
        if (navigatorDescriptor) Object.defineProperty(global, 'navigator', navigatorDescriptor);
        else delete global.navigator;
        global.setTimeout = prevSetTimeout;
    }

    assert.ok(notificationEl.textContent.indexOf('Copy failed') !== -1,
        `a denied write must notify, got "${notificationEl.textContent}"`);
});

// --- Bulk controller (makeBulkController) ------------------------------------
//
// The factory drives every list's selection state; these tests pin the
// count label, the select-all indicator and the row resolution.

function stubBulkDocument(boxes, countEl, selectAll) {
    return {
        getElementById(id) { return id === 'bulk-count' ? countEl : null; },
        querySelector(sel) { return sel === '[data-action="select-all"]' ? selectAll : null; },
        querySelectorAll(sel) { return sel === '.bulk-box' ? boxes : []; }
    };
}

test('makeBulkController.updateCount reports the selection and syncs select-all', () => {
    const countEl = { textContent: '' };
    const selectAll = { checked: false };
    const boxes = [
        { checked: true, closest: () => ({ id: 'r1' }) },
        { checked: true, closest: () => ({ id: 'r2' }) },
        { checked: false, closest: () => ({ id: 'r3' }) }
    ];
    const doc = stubBulkDocument(boxes, countEl, selectAll);

    const ctrl = app.makeBulkController({
        name: 'zones', checkboxClass: 'bulk-box', countId: 'bulk-count',
        noun: 'zone', selectAllAction: 'select-all', deleteAction: 'd',
        barId: 'bar', endpoint: '/zones/bulk-delete',
        idField: 'zone_id', idAttr: 'data-zone-id', failedSuffix: null
    });

    withDocument(doc, () => ctrl.updateCount());
    assert.strictEqual(countEl.textContent, '2 zones selected');
    assert.strictEqual(selectAll.checked, false, 'select-all stays off with a partial selection');

    boxes[2].checked = true;
    withDocument(doc, () => ctrl.updateCount());
    assert.strictEqual(countEl.textContent, '3 zones selected');
    assert.strictEqual(selectAll.checked, true, 'select-all flips on when every box is checked');

    // Singular noun for a single item.
    boxes[1].checked = false;
    boxes[2].checked = false;
    withDocument(doc, () => ctrl.updateCount());
    assert.strictEqual(countEl.textContent, '1 zone selected');
});

test('makeBulkController.selectedRows resolves the checked rows', () => {
    const row1 = { id: 'r1' };
    const row2 = { id: 'r2' };
    const boxes = [
        { checked: true, closest: () => row1 },
        { checked: false, closest: () => row2 }
    ];
    const doc = stubBulkDocument(boxes, { textContent: '' }, { checked: false });
    const ctrl = app.makeBulkController({
        name: 'zones', checkboxClass: 'bulk-box', countId: 'bulk-count',
        noun: 'zone', selectAllAction: 'select-all', deleteAction: 'd',
        barId: 'bar', endpoint: '/zones/bulk-delete',
        idField: 'zone_id', idAttr: 'data-zone-id', failedSuffix: null
    });
    withDocument(doc, () => {
        const rows = ctrl.selectedRows();
        assert.strictEqual(rows.length, 1);
        assert.strictEqual(rows[0], row1);
    });
});

// --- Per-page selector (applyPerPage) ----------------------------------------

test('applyPerPage builds the href from window.location', () => {
    const select = { attrs: { 'data-prefix': 'log' }, value: '20' };
    select.getAttribute = function(name) { return Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name] : null; };
    const searchInput = { value: 'foo' };

    const doc = stubDocument();
    doc.querySelector = () => searchInput;

    const prevDocument = global.document;
    const prevWindow = global.window;
    let captured = '';
    global.document = doc;
    global.window = {
        location: {
            search: '?logPage=3&logPerPage=10&Page=2&search=foo',
            get href() { return ''; },
            set href(v) { captured = v; }
        }
    };
    try {
        app.applyPerPage(select);
    } finally {
        global.document = prevDocument;
        global.window = prevWindow;
    }

    const params = new URLSearchParams(captured.replace(/^\?/, ''));
    assert.strictEqual(params.get('logPerPage'), '20', 'this section size changes');
    assert.strictEqual(params.has('logPage'), false, 'this section page resets');
    assert.strictEqual(params.get('Page'), '2', 'the other section is preserved');
    assert.strictEqual(params.get('search'), 'foo', 'the search is preserved');
});

test('applyPerPage drops an emptied search and works with no prefix', () => {
    const select = { attrs: {}, value: '0' };
    select.getAttribute = function(name) { return Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name] : null; };
    const searchInput = { value: '' };

    const doc = stubDocument();
    doc.querySelector = () => searchInput;

    const prevDocument = global.document;
    const prevWindow = global.window;
    let captured = '';
    global.document = doc;
    global.window = {
        location: {
            search: '?Page=7&PerPage=10&search=old',
            set href(v) { captured = v; }
        }
    };
    try {
        app.applyPerPage(select);
    } finally {
        global.document = prevDocument;
        global.window = prevWindow;
    }

    const params = new URLSearchParams(captured.replace(/^\?/, ''));
    assert.strictEqual(params.get('PerPage'), '0', 'All');
    assert.strictEqual(params.has('Page'), false, 'page resets');
    assert.strictEqual(params.has('search'), false, 'an emptied search is dropped');
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
    doc.setElement('notification', withClassList({ textContent: '', className: 'notification hidden' }));
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
