// Loaded in <head> on every page so a saved choice applies before first paint.
// Two display preferences live here, theme and text size. Both are read and
// applied at the top of this function, before anything renders, so the page
// never shows one setting and then jumps to another.
(function () {
    var root = document.documentElement;
    var KEY = 'theme';
    var SIZE_KEY = 'text-size';
    // Index 0 is the reader's own browser setting, untouched. The other two
    // are multipliers of it, applied by the html[data-text-size] rules.
    var SIZES = ['default', 'large', 'largest'];
    var saved = null;
    try { saved = localStorage.getItem(KEY); } catch (e) { /* storage blocked */ }
    if (saved === 'light' || saved === 'dark') root.setAttribute('data-theme', saved);

    var savedSize = null;
    try { savedSize = localStorage.getItem(SIZE_KEY); } catch (e) { /* storage blocked */ }
    if (SIZES.indexOf(savedSize) > 0) root.setAttribute('data-text-size', savedSize);

    function current() {
        var chosen = root.getAttribute('data-theme');
        if (chosen) return chosen;
        var mq = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)');
        return mq && mq.matches ? 'light' : 'dark';
    }

    function relabel(btn) {
        var next = current() === 'dark' ? 'light' : 'dark';
        btn.setAttribute('aria-label', 'Switch to ' + next + ' theme');
        btn.title = 'Switch to ' + next + ' theme';
    }

    function currentSize() {
        var chosen = root.getAttribute('data-text-size');
        return SIZES.indexOf(chosen) > 0 ? chosen : SIZES[0];
    }

    function nextSize() {
        return SIZES[(SIZES.indexOf(currentSize()) + 1) % SIZES.length];
    }

    function relabelSize(btn) {
        // Both the size now in effect and the one a click gives, because the
        // button is a cycle: without the first half a reader cannot tell where
        // they are in it, and without the second they cannot tell where a
        // click takes them.
        var label = 'Text size: ' + currentSize() + '. Switch to ' + nextSize() + '.';
        btn.setAttribute('aria-label', label);
        btn.title = label;
    }

    function initTheme() {
        var btn = document.getElementById('theme-toggle');
        if (!btn) return;
        relabel(btn);
        btn.addEventListener('click', function () {
            var next = current() === 'dark' ? 'light' : 'dark';
            root.setAttribute('data-theme', next);
            try { localStorage.setItem(KEY, next); } catch (e) { /* storage blocked */ }
            relabel(btn);
        });
        var mq = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)');
        if (mq && mq.addEventListener) {
            mq.addEventListener('change', function () {
                if (!root.getAttribute('data-theme')) relabel(btn);
            });
        }
    }

    function initTextSize() {
        var btn = document.getElementById('text-size-toggle');
        if (!btn) return;
        relabelSize(btn);
        btn.addEventListener('click', function () {
            var next = nextSize();
            if (next === SIZES[0]) {
                // Back to the reader's own setting: remove the attribute
                // rather than write a "default" the CSS would have to know
                // about, and drop the stored value so nothing is carried.
                root.removeAttribute('data-text-size');
                try { localStorage.removeItem(SIZE_KEY); } catch (e) { /* storage blocked */ }
            } else {
                root.setAttribute('data-text-size', next);
                try { localStorage.setItem(SIZE_KEY, next); } catch (e) { /* storage blocked */ }
            }
            relabelSize(btn);
        });
    }

    function init() {
        initTheme();
        initTextSize();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
