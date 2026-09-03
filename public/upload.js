/* Mt. Zion Capital — secure upload page (client side).
   Talks only to /api/upload/* on this same origin. No third-party code except
   Cloudflare Turnstile, which is loaded only when the site owner has enabled it. */
(function () {
  'use strict';

  var API = '/api/upload';
  var $ = function (id) { return document.getElementById(id); };

  var yearEl = $('year');
  if (yearEl) yearEl.textContent = new Date().getFullYear();

  var params = new URLSearchParams(window.location.search);
  var linkToken = (params.get('c') || '').trim();

  var config = null;
  var turnstileToken = '';
  var turnstileWidgetId = null;
  var queue = []; // { file, status, problem, li, fill, meta, rm }

  var steps = { auth: $('step-auth'), upload: $('step-upload'), done: $('step-done'), message: $('step-message') };

  function show(name) {
    Object.keys(steps).forEach(function (k) { if (steps[k]) steps[k].hidden = true; });
    if (steps[name]) steps[name].hidden = false;
    if (name === 'auth') { var pw = $('password'); if (pw) pw.focus(); }
  }

  function showMessage(title, body) {
    $('message-title').textContent = title;
    $('message-body').textContent = body;
    show('message');
  }

  function setError(id, msg) {
    var el = $(id);
    if (!el) return;
    if (!msg) { el.hidden = true; el.textContent = ''; }
    else { el.textContent = msg; el.hidden = false; }
  }

  function fmtSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(0) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  function api(path, opts) {
    opts = opts || {};
    var headers = Object.assign({ 'X-Requested-With': 'mzc-upload' }, opts.headers || {});
    return fetch(API + path, Object.assign({ credentials: 'same-origin', cache: 'no-store' }, opts, { headers: headers }))
      .then(function (res) {
        return res.json().catch(function () { return null; }).then(function (data) {
          return { res: res, data: data || { ok: false, error: 'bad_response' } };
        });
      });
  }

  // ---------- Boot ----------
  function init() {
    api('/config').then(function (r) {
      if (!r.res.ok || !r.data.ok) throw new Error('config');
      config = r.data;
      afterConfig();
    }).catch(function () {
      showMessage(
        'This page is temporarily unavailable',
        'The secure upload service could not be reached. Please make sure you are at www.mtzioncapital.com/upload, or email us at sales@mtzioncapital.com.'
      );
    });
  }

  function afterConfig() {
    if (!config.ready) {
      showMessage('Almost ready', 'The secure upload portal is not fully set up yet. Please email sales@mtzioncapital.com and we will arrange another way to receive your documents.');
      return;
    }
    if (config.requireClientLink && !linkToken) {
      showMessage('A personal upload link is required', 'For your security, uploads need the personal link we sent you. If you need a new one, email sales@mtzioncapital.com.');
      return;
    }

    $('dropzone-hint').textContent = 'PDF, photos (JPG, PNG, HEIC), Word, Excel, CSV or ZIP. Up to ' + config.maxFileMB + ' MB each.';
    var ret = $('retention-days');
    if (ret) ret.textContent = config.retentionDays;
    $('file-input').setAttribute('accept', config.allowedExt.map(function (e) { return '.' + e; }).join(','));

    api('/session').then(function (s) {
      if (s.res.ok && s.data.ok) { enterUpload(s.data); return; }
      if (linkToken) $('link-pill').hidden = false;
      setupTurnstile();
      show('auth');
    });
  }

  // ---------- Turnstile (only if the owner configured a site key) ----------
  function setupTurnstile() {
    if (!config.turnstileSiteKey) return;
    var container = $('turnstile');
    container.hidden = false;
    window.__mzcTurnstileReady = function () {
      turnstileWidgetId = window.turnstile.render(container, {
        sitekey: config.turnstileSiteKey,
        theme: 'light',
        callback: function (t) { turnstileToken = t; },
        'expired-callback': function () { turnstileToken = ''; },
        'error-callback': function () { turnstileToken = ''; }
      });
    };
    var s = document.createElement('script');
    s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=__mzcTurnstileReady';
    s.async = true;
    s.defer = true;
    document.head.appendChild(s);
  }

  function resetTurnstile() {
    turnstileToken = '';
    if (turnstileWidgetId !== null && window.turnstile) {
      try { window.turnstile.reset(turnstileWidgetId); } catch (e) { /* ignore */ }
    }
  }

  // ---------- Step 1: password ----------
  $('auth-form').addEventListener('submit', function (e) {
    e.preventDefault();
    setError('auth-error', '');
    var pw = $('password').value;
    if (!pw && !linkToken) { setError('auth-error', 'Please enter the password.'); return; }
    if (config.turnstileSiteKey && !turnstileToken) {
      setError('auth-error', 'Give the security check a moment to finish, then try again.');
      return;
    }
    var btn = $('auth-submit');
    btn.disabled = true;
    btn.textContent = 'Checking';

    api('/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pw, c: linkToken, turnstile: turnstileToken })
    }).then(function (r) {
      btn.disabled = false;
      btn.textContent = 'Continue';
      if (r.res.ok && r.data.ok) { $('password').value = ''; enterUpload(r.data); return; }
      setError('auth-error', r.data.message || 'Something went wrong. Please try again.');
      resetTurnstile();
    }).catch(function () {
      btn.disabled = false;
      btn.textContent = 'Continue';
      setError('auth-error', 'Network problem. Please check your connection and try again.');
    });
  });

  function enterUpload(session) {
    var who = $('upload-who');
    if (session && session.label) { who.textContent = 'Uploading as: ' + session.label; who.hidden = false; }
    else { who.hidden = true; }
    show('upload');
  }

  // ---------- Step 2: files ----------
  var input = $('file-input');
  var drop = $('dropzone');
  var list = $('file-list');
  var submit = $('upload-submit');

  drop.addEventListener('click', function () { input.click(); });
  drop.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
  });
  ['dragenter', 'dragover'].forEach(function (ev) {
    drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add('is-over'); });
  });
  ['dragleave', 'drop'].forEach(function (ev) {
    drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove('is-over'); });
  });
  drop.addEventListener('drop', function (e) { addFiles(e.dataTransfer.files); });
  input.addEventListener('change', function () { addFiles(input.files); input.value = ''; });

  function addFiles(files) {
    setError('upload-error', '');
    Array.prototype.forEach.call(files, function (file) {
      var ext = (file.name.split('.').pop() || '').toLowerCase();
      var problem = '';
      if (config.allowedExt.indexOf(ext) === -1) problem = 'File type not accepted';
      else if (file.size > config.maxFileMB * 1024 * 1024) problem = 'Larger than ' + config.maxFileMB + ' MB';
      else if (file.size === 0) problem = 'Empty file';
      var item = { file: file, status: problem ? 'rejected' : 'ready', problem: problem };
      item.li = renderItem(item);
      list.appendChild(item.li);
      queue.push(item);
    });
    updateSubmit();
  }

  function renderItem(item) {
    var li = document.createElement('li');
    li.className = 'file-row ' + item.status;

    var name = document.createElement('span');
    name.className = 'file-name';
    name.textContent = item.file.name;

    var meta = document.createElement('span');
    meta.className = 'file-meta';
    meta.textContent = item.problem || fmtSize(item.file.size);

    var bar = document.createElement('span');
    bar.className = 'file-bar';
    var fill = document.createElement('span');
    fill.className = 'file-fill';
    bar.appendChild(fill);

    var rm = document.createElement('button');
    rm.type = 'button';
    rm.className = 'file-remove';
    rm.setAttribute('aria-label', 'Remove ' + item.file.name);
    rm.textContent = '×';
    rm.addEventListener('click', function () {
      queue = queue.filter(function (q) { return q !== item; });
      li.remove();
      updateSubmit();
    });

    li.appendChild(name);
    li.appendChild(meta);
    li.appendChild(bar);
    li.appendChild(rm);
    item.fill = fill;
    item.meta = meta;
    item.rm = rm;
    return li;
  }

  function updateSubmit() {
    submit.disabled = !queue.some(function (q) { return q.status === 'ready'; });
  }

  function lockInputs(lock) {
    ['uploader-name', 'uploader-company', 'uploader-note'].forEach(function (id) { $(id).disabled = lock; });
    drop.classList.toggle('is-locked', lock);
    $('finish-btn').disabled = lock;
  }

  $('upload-form').addEventListener('submit', function (e) {
    e.preventDefault();
    setError('upload-error', '');
    var ready = queue.filter(function (q) { return q.status === 'ready'; });
    if (!ready.length) return;

    submit.disabled = true;
    submit.textContent = 'Uploading';
    lockInputs(true);

    var sent = 0, failed = 0, expired = false;

    // Upload one at a time so progress is clear and memory use stays low.
    ready.reduce(function (chain, item) {
      return chain.then(function () {
        if (expired) return;
        item.status = 'uploading';
        item.li.className = 'file-row uploading';
        item.rm.disabled = true;
        return sendFile(item).then(function (result) {
          if (result.ok) {
            item.status = 'done';
            item.li.className = 'file-row done';
            item.meta.textContent = 'Uploaded';
            sent++;
          } else {
            item.status = result.expired ? 'ready' : 'failed';
            item.li.className = 'file-row ' + item.status;
            item.meta.textContent = result.message || 'Failed';
            item.rm.disabled = false;
            item.fill.style.width = '0%';
            failed++;
            if (result.expired) expired = true;
          }
        });
      });
    }, Promise.resolve()).then(function () {
      lockInputs(false);
      submit.textContent = 'Upload files';
      updateSubmit();
      if (expired) {
        show('auth');
        setupTurnstileIfNeeded();
        setError('auth-error', 'Your session timed out. Enter the password again and your remaining files will still be listed.');
        return;
      }
      if (sent && !failed) {
        $('done-count').textContent = sent === 1 ? 'your file' : 'your ' + sent + ' files';
        show('done');
      } else if (failed) {
        setError('upload-error', 'Some files could not be uploaded. See the note next to each file, then try again.');
      }
    });
  });

  function setupTurnstileIfNeeded() {
    if (config.turnstileSiteKey && turnstileWidgetId === null) setupTurnstile();
    else resetTurnstile();
  }

  function sendFile(item) {
    return new Promise(function (resolve) {
      var xhr = new XMLHttpRequest();
      xhr.open('POST', API + '/file');
      xhr.setRequestHeader('X-Requested-With', 'mzc-upload');
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');
      xhr.setRequestHeader('X-File-Name', encodeURIComponent(item.file.name));
      xhr.setRequestHeader('X-Uploader-Name', encodeURIComponent($('uploader-name').value.trim()));
      xhr.setRequestHeader('X-Uploader-Company', encodeURIComponent($('uploader-company').value.trim()));
      xhr.setRequestHeader('X-Uploader-Note', encodeURIComponent($('uploader-note').value.trim()));
      xhr.upload.onprogress = function (ev) {
        if (ev.lengthComputable) item.fill.style.width = Math.round((ev.loaded / ev.total) * 100) + '%';
      };
      xhr.onload = function () {
        var d = {};
        try { d = JSON.parse(xhr.responseText); } catch (e) { d = {}; }
        if (xhr.status >= 200 && xhr.status < 300 && d.ok) {
          item.fill.style.width = '100%';
          resolve({ ok: true });
        } else {
          resolve({ ok: false, expired: xhr.status === 401, message: d.message || ('Upload failed (' + xhr.status + ')') });
        }
      };
      xhr.onerror = function () { resolve({ ok: false, message: 'Network error. Please try again.' }); };
      xhr.send(item.file);
    });
  }

  // ---------- Finish / more ----------
  function finish() {
    api('/logout', { method: 'POST' }).catch(function () { /* ignore */ }).then(function () {
      queue = [];
      list.textContent = '';
      $('password').value = '';
      ['uploader-name', 'uploader-company', 'uploader-note'].forEach(function (id) { $(id).value = ''; });
      setError('auth-error', '');
      setError('upload-error', '');
      setupTurnstileIfNeeded();
      show('auth');
    });
  }
  $('finish-btn').addEventListener('click', finish);
  $('done-finish').addEventListener('click', finish);

  $('more-btn').addEventListener('click', function () {
    queue = queue.filter(function (q) { return q.status !== 'done'; });
    Array.prototype.forEach.call(list.querySelectorAll('.file-row.done'), function (li) { li.remove(); });
    show('upload');
    updateSubmit();
  });

  init();
})();
