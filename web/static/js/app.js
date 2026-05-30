// gozone - PowerDNS Admin Interface
console.log('gozone - PowerDNS Admin Interface');

(function() {
    var theme = localStorage.getItem('gozone-theme') || 'light';
    document.documentElement.setAttribute('data-theme', theme);
})();

function toggleTheme() {
    var current = document.documentElement.getAttribute('data-theme');
    var next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('gozone-theme', next);
}
