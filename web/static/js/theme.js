// gozone theme bootstrap — runs synchronously in <head> before the body is
// painted, applying the persisted colour theme to <html> so there is no flash
// of the default (light) theme on navigation (FOUC). Kept in a separate 'self'
// file (not inline) so the Content-Security-Policy script-src 'self' is
// respected. The full UI (sidebar state, toggle icon) is wired up later by
// app.js, which runs at the end of <body> and needs the body DOM.
(function() {
    var theme = 'light';
    try {
        theme = localStorage.getItem('gozone-theme') || 'light';
    } catch (e) {
        // localStorage can be unavailable (private mode / blocked cookies);
        // fall back to the default light theme rather than throwing in the
        // critical <head> path.
    }
    document.documentElement.setAttribute('data-theme', theme);
})();
