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
