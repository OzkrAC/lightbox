// lightbox-docs.js: the vocabulary, the navigation and the behaviours of the
// lightbox documentation. Every page lists it in its :::use block, after the
// themes and before docs.css. The engine provides window.luccet before an
// add-on runs, and `luccet check` runs this file too, so the command line knows
// the same names as the browser. Behaviours do nothing under the command line.
//
// The layout follows Luccet's own documentation: the navigation is a sidebar
// on a wide screen and a bar with a Menu button on a narrow one, the page's
// contents are a card under its title, and every fence has a Copy button.
(function () {
  'use strict';
  var luccet = window.luccet;
  if (!luccet) return;

  // The release these pages describe, shown beside the name in the navigation
  // of every page: the one place to change when the pages are brought up to a
  // new release.
  var VERSION = '0.10.0';
  var REPO = 'https://github.com/OzkrAC/lightbox';

  // The pages, in the order of the navigation. The first is the home page,
  // which the name at the top of the navigation leads to.
  var PAGES = [
    ['index.html', 'lightbox'],
    ['guide.html', 'Getting started'],
    ['commands.html', 'Commands'],
    ['configuration.html', 'Configuration'],
    ['storage.html', 'Storage'],
    ['networking.html', 'Networking'],
    ['security.html', 'Security'],
    ['agents.html', 'Agent boxes'],
    ['internals.html', 'How it works'],
    ['troubleshooting.html', 'Troubleshooting'],
  ];

  // What is not a page of these: under a heading of its own, after the pages.
  var PROJECT = [
    [REPO, 'Source'],
    [REPO + '/blob/main/CHANGELOG.md', 'Changelog'],
    [REPO + '/issues', 'Issues'],
  ];

  // ------------------------------------------------------------- vocabulary

  // Callouts: asides with a label, coloured by name in docs.css.
  var callouts = {
    note: 'Note',
    tip: 'Tip',
    important: 'Important',
    warning: 'Warning',
    danger: 'Danger',
  };
  Object.keys(callouts).forEach(function (name) {
    luccet.block(name, { tag: 'aside', class: 'callout', attrs: { role: 'note' }, label: callouts[name] });
  });

  // A member: one entry of a reference, such as a setting, a file or a check.
  // Its first fence is its header, and the rest its description.
  luccet.block('member', { tag: 'section' });

  // `::toc` lists the page's own headings.
  luccet.leaf('toc', {
    tag: 'nav',
    transform: 'toc',
    depth: '2-3',
    label: 'Contents',
    attrs: { 'aria-label': 'Contents' },
  });

  // `::site-nav` is the site's navigation, filled in below.
  luccet.leaf('site-nav', { tag: 'nav', attrs: { 'aria-label': 'Site' } });

  // ------------------------------------------------------------- behaviours

  // An element with its attributes and children. A null attribute is left out.
  function el(tag, attrs) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (key) {
      if (attrs[key] !== null && attrs[key] !== undefined) node.setAttribute(key, attrs[key]);
    });
    for (var i = 2; i < arguments.length; i++) node.append(arguments[i]);
    return node;
  }

  // The navigation: the name and the release, a Menu button that a narrow
  // screen shows, and the list of pages. The current page is marked with
  // aria-current, which docs.css draws as a bar, and not by colour alone.
  luccet.define('site-nav', function (nav) {
    var here = location.pathname.split('/').pop() || 'index.html';
    var current = function (path) { return path === here ? 'page' : null; };
    var item = function (page) {
      return el('li', null, el('a', { href: page[0], 'aria-current': current(page[0]) }, page[1]));
    };
    var home = PAGES[0];
    var list = el('ul', { 'class': 'docs-nav-list', id: 'docs-nav-list' });
    PAGES.slice(1).forEach(function (page) { list.append(item(page)); });
    var project = el('ul', { 'aria-labelledby': 'docs-nav-project' });
    PROJECT.forEach(function (page) { project.append(item(page)); });
    list.append(el('li', { 'class': 'docs-nav-group' },
      el('span', { 'class': 'docs-nav-heading', id: 'docs-nav-project' }, 'Project'), project));

    var toggle = el('button', { type: 'button', 'class': 'docs-nav-toggle', 'aria-expanded': 'false', 'aria-controls': 'docs-nav-list' }, 'Menu');
    toggle.addEventListener('click', function () {
      var open = toggle.getAttribute('aria-expanded') !== 'true';
      toggle.setAttribute('aria-expanded', String(open));
      nav.classList.toggle('docs-nav-open', open);
    });
    var version = el('a', {
      'class': 'docs-nav-version',
      href: REPO + '/blob/main/CHANGELOG.md',
      title: 'These pages describe lightbox ' + VERSION + '. The changelog has every release.',
    }, VERSION);
    var bar = el('div', { 'class': 'docs-nav-bar' },
      el('span', { 'class': 'docs-nav-name' },
        el('a', { 'class': 'docs-nav-home', href: home[0], 'aria-current': current(home[0]) }, home[1]), version),
      toggle);
    nav.replaceChildren(bar, list);
    // for docs.css, where a browser has no :has(): the page makes room for the sidebar
    document.documentElement.classList.add('docs-has-nav');
  });

  // A Copy button on every fence. It copies the code as written. Of a
  // `console` fence, which shows commands with what they print, it copies the
  // commands alone, without their prompts, as those are what a reader types.
  var copyStatus = null;
  function copied(code) {
    var text = code.textContent;
    if (!code.classList.contains('language-console')) return text;
    var commands = text.split('\n').filter(function (line) { return /^[#$] /.test(line); });
    return commands.length ? commands.map(function (line) { return line.slice(2); }).join('\n') + '\n' : text;
  }
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).then(function () { return true; }, function () { return selectAndCopy(text); });
    }
    return Promise.resolve(selectAndCopy(text));
  }
  function selectAndCopy(text) {
    var area = el('textarea', { readonly: '', 'aria-hidden': 'true', 'class': 'docs-copy-status' });
    area.value = text;
    document.body.append(area);
    area.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    area.remove();
    return ok;
  }
  luccet.define('code', function (node) {
    var pre = node.matches('pre') ? node : node.querySelector(':scope > pre');
    var code = pre && pre.querySelector(':scope > code');
    if (!code || pre.querySelector(':scope > .docs-copy')) return;
    var button = el('button', { type: 'button', 'class': 'docs-copy' }, 'Copy');
    var timer = 0;
    button.addEventListener('click', function () {
      copyText(copied(code)).then(function (ok) {
        var word = ok ? 'Copied' : 'Copy failed';
        button.textContent = word;
        button.setAttribute('data-done', ok ? 'yes' : 'no');
        if (!copyStatus || !copyStatus.isConnected) {
          copyStatus = el('div', { 'class': 'docs-copy-status', role: 'status' });
          document.body.append(copyStatus);
        }
        copyStatus.textContent = word;
        clearTimeout(timer);
        timer = setTimeout(function () {
          button.textContent = 'Copy';
          button.removeAttribute('data-done');
        }, 1800);
      });
    });
    pre.classList.add('docs-copyable');
    pre.prepend(button);
  });

  // A heading with an id gets a link to itself, shown beside it on hover, so
  // that a section of a reference can be linked to. And a short piece of code
  // in the text, such as an option, is marked so that docs.css keeps it on one
  // line: a browser would otherwise break `--privileged` after its dashes.
  luccet.on('render', function () {
    var spans = document.querySelectorAll('main.luccet code');
    Array.prototype.forEach.call(spans, function (code) {
      if (code.parentNode.nodeName !== 'PRE' && code.textContent.length <= 32) code.classList.add('short');
    });
    var headings = document.querySelectorAll('main.luccet h2[id], main.luccet h3[id], main.luccet h4[id]');
    Array.prototype.forEach.call(headings, function (h) {
      if (h.querySelector('a.anchor')) return;
      var a = el('a', { href: '#' + h.id, 'class': 'anchor', 'aria-label': 'Link to this section' }, '#');
      h.appendChild(a);
    });
  });
})();
