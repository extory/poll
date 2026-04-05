/**
 * i18n — lightweight internationalization
 * Usage:
 *   <span data-i18n="key">한국어 기본값</span>
 *   <input data-i18n-placeholder="key" placeholder="한국어">
 *   <button data-i18n="key">한국어</button>
 *
 * JS: i18n.t('key')
 */
const i18n = (() => {
  const STORAGE_KEY = 'poll_lang';
  let currentLang = (() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) return stored;
    const nav = navigator.language || '';
    if (nav.startsWith('ko')) return 'ko';
    if (nav.startsWith('ja')) return 'ja';
    return 'en';
  })();

  let translations = {};

  function setTranslations(data) {
    translations = data;
  }

  function t(key) {
    return translations[currentLang]?.[key] || translations['ko']?.[key] || key;
  }

  function getLang() {
    return currentLang;
  }

  function setLang(lang) {
    currentLang = lang;
    localStorage.setItem(STORAGE_KEY, lang);
    applyAll();
    // Update toggle buttons
    document.querySelectorAll('.lang-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.lang === lang);
    });
    document.documentElement.lang = lang;
  }

  function applyAll() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      const val = t(key);
      if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
        el.value = val;
      } else {
        el.innerHTML = val;
      }
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
      el.placeholder = t(el.getAttribute('data-i18n-placeholder'));
    });
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
      el.title = t(el.getAttribute('data-i18n-title'));
    });
  }

  // Language toggle component
  function renderToggle(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = `
      <button class="lang-btn ${currentLang === 'ko' ? 'active' : ''}" data-lang="ko" onclick="i18n.setLang('ko')">KO</button>
      <button class="lang-btn ${currentLang === 'en' ? 'active' : ''}" data-lang="en" onclick="i18n.setLang('en')">EN</button>
      <button class="lang-btn ${currentLang === 'ja' ? 'active' : ''}" data-lang="ja" onclick="i18n.setLang('ja')">JA</button>
    `;
  }

  // Auto-apply on load
  function init(data, toggleId) {
    setTranslations(data);
    if (toggleId) renderToggle(toggleId);
    applyAll();
  }

  return { init, t, getLang, setLang, setTranslations, applyAll, renderToggle };
})();
