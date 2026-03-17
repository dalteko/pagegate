(() => {
  // Elements
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const fileInfo = document.getElementById('fileInfo');
  const previewSection = document.getElementById('previewSection');
  const previewFrame = document.getElementById('previewFrame');
  const removeFileBtn = document.getElementById('removeFile');
  const passwordSection = document.getElementById('passwordSection');
  const passwordInput = document.getElementById('passwordInput');
  const generateBtn = document.getElementById('generateBtn');
  const resultSection = document.getElementById('resultSection');
  const linkOutput = document.getElementById('linkOutput');
  const copyBtn = document.getElementById('copyBtn');
  const expirationNote = document.getElementById('expirationNote');
  const resetBtn = document.getElementById('resetBtn');

  const historySection = document.getElementById('historySection');
  const historyList = document.getElementById('historyList');
  const clearHistoryBtn = document.getElementById('clearHistoryBtn');

  const MAX_SIZE = 5 * 1024 * 1024; // 5MB
  const STORAGE_KEY = 'pagegate_history';
  let currentFile = null;

  // === Rotating tagline ===
  const items = document.querySelectorAll('.rotating-item');
  let activeIndex = 0;

  setInterval(() => {
    items[activeIndex].classList.remove('active');
    activeIndex = (activeIndex + 1) % items.length;
    items[activeIndex].classList.add('active');
  }, 3000);

  // === Drag and drop ===
  dropzone.addEventListener('click', () => fileInput.click());

  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });

  dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('dragover');
  });

  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    const files = e.dataTransfer.files;
    if (files.length > 0) handleFile(files[0]);
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) handleFile(fileInput.files[0]);
  });

  // === File handling ===
  function handleFile(file) {
    fileInfo.textContent = '';

    // Validate extension
    const ext = file.name.split('.').pop().toLowerCase();
    if (ext !== 'html' && ext !== 'htm') {
      fileInfo.textContent = 'Only .html files are accepted.';
      return;
    }

    // Validate size
    if (file.size > MAX_SIZE) {
      fileInfo.textContent = 'File must be under 5MB.';
      return;
    }

    currentFile = file;
    loadPreview(file);
  }

  function loadPreview(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      const html = e.target.result;
      // Write to sandboxed iframe
      previewFrame.srcdoc = html;

      // Show preview and password sections
      previewSection.classList.remove('hidden');
      passwordSection.classList.remove('hidden');
      resultSection.classList.add('hidden');

      // Hide the dropzone
      dropzone.style.display = 'none';
      fileInfo.textContent = '';

      // Focus password field
      setTimeout(() => passwordInput.focus(), 300);
    };
    reader.readAsText(file);
  }

  // === Remove file ===
  removeFileBtn.addEventListener('click', resetAll);

  // === Generate link ===
  generateBtn.addEventListener('click', async () => {
    const password = passwordInput.value.trim();
    if (!password) {
      passwordInput.style.borderColor = '#EF4444';
      passwordInput.focus();
      return;
    }
    passwordInput.style.borderColor = '';
    fileInfo.textContent = '';

    generateBtn.disabled = true;
    generateBtn.textContent = 'Uploading...';

    try {
      const formData = new FormData();
      formData.append('file', currentFile);
      formData.append('password', password);

      const res = await fetch('/api/upload', { method: 'POST', body: formData });
      const data = await res.json();

      if (!res.ok) {
        fileInfo.textContent = data.error || 'Upload failed';
        return;
      }

      // Format expiration date
      const expDate = new Date(data.expiresAt);
      const expStr = expDate.toLocaleDateString('en-US', {
        month: 'long',
        day: 'numeric',
        year: 'numeric',
      });

      linkOutput.value = data.url;
      expirationNote.textContent = `Expires ${expStr}`;
      resultSection.classList.remove('hidden');
      passwordSection.classList.add('hidden');

      // Save to history (no password stored — users should use a password manager)
      saveToHistory({
        url: data.url,
        filename: currentFile.name,
        createdAt: new Date().toISOString(),
        expiresAt: data.expiresAt,
      });

      resultSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
    } catch {
      fileInfo.textContent = 'Upload failed. Please try again.';
    } finally {
      generateBtn.disabled = false;
      generateBtn.textContent = 'Generate Link';
    }
  });

  // Password input — clear error on type
  passwordInput.addEventListener('input', () => {
    passwordInput.style.borderColor = '';
  });

  // Enter key in password field triggers generate
  passwordInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') generateBtn.click();
  });

  // === Copy link ===
  copyBtn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(linkOutput.value);
      copyBtn.textContent = 'Copied!';
      copyBtn.classList.add('copied');
      setTimeout(() => {
        copyBtn.textContent = 'Copy';
        copyBtn.classList.remove('copied');
      }, 2000);
    } catch {
      // Fallback
      linkOutput.select();
      document.execCommand('copy');
    }
  });

  // === Reset ===
  resetBtn.addEventListener('click', resetAll);

  function resetAll() {
    currentFile = null;
    fileInput.value = '';
    passwordInput.value = '';
    fileInfo.textContent = '';
    previewFrame.srcdoc = '';
    dropzone.style.display = '';
    previewSection.classList.add('hidden');
    passwordSection.classList.add('hidden');
    resultSection.classList.add('hidden');
    copyBtn.textContent = 'Copy';
    copyBtn.classList.remove('copied');
  }

  // === History (localStorage) ===
  function getHistory() {
    try {
      const history = JSON.parse(localStorage.getItem(STORAGE_KEY)) || [];
      // Migrate: strip any plaintext passwords from older entries
      let migrated = false;
      for (const entry of history) {
        if (entry.password) {
          delete entry.password;
          migrated = true;
        }
      }
      if (migrated) localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
      return history;
    } catch {
      return [];
    }
  }

  function saveToHistory(entry) {
    const history = getHistory();
    // Avoid duplicates by URL
    const filtered = history.filter(h => h.url !== entry.url);
    filtered.unshift(entry);
    // Keep max 20 entries
    localStorage.setItem(STORAGE_KEY, JSON.stringify(filtered.slice(0, 20)));
    renderHistory();
  }

  function removeFromHistory(url) {
    const history = getHistory().filter(h => h.url !== url);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
    renderHistory();
  }

  function clearHistory() {
    localStorage.removeItem(STORAGE_KEY);
    renderHistory();
  }

  function renderHistory() {
    const history = getHistory();
    historyList.innerHTML = '';

    if (history.length === 0) {
      historySection.classList.add('hidden');
      return;
    }

    historySection.classList.remove('hidden');
    const now = new Date();

    history.forEach(entry => {
      const item = document.createElement('div');
      item.className = 'history-item';

      const expires = new Date(entry.expiresAt);
      const daysLeft = Math.ceil((expires - now) / (1000 * 60 * 60 * 24));
      const isExpired = daysLeft <= 0;

      let metaText;
      if (isExpired) {
        metaText = '<span class="expired">Expired</span>';
      } else if (daysLeft === 1) {
        metaText = '1 day left';
      } else {
        metaText = `${daysLeft} days left`;
      }

      item.innerHTML = `
        <div class="history-item-info">
          <div class="history-item-name">${escapeHtml(entry.filename)}</div>
          <div class="history-item-meta">${metaText}</div>
        </div>
        <div class="history-item-actions">
          <button class="btn-icon btn-icon--copy" data-url="${escapeAttr(entry.url)}" title="Copy link">Copy</button>
          <button class="btn-icon btn-icon--open" data-url="${escapeAttr(entry.url)}" title="Open page">Open</button>
          <button class="btn-icon btn-icon--delete" data-url="${escapeAttr(entry.url)}" title="Remove">&times;</button>
        </div>
      `;

      historyList.appendChild(item);
    });
  }

  // Delegated click handler for history actions
  historyList.addEventListener('click', async (e) => {
    const btn = e.target.closest('.btn-icon');
    if (!btn) return;

    if (btn.classList.contains('btn-icon--copy')) {
      try {
        await navigator.clipboard.writeText(btn.dataset.url);
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1500);
      } catch { /* ignore */ }
    } else if (btn.classList.contains('btn-icon--open')) {
      window.open(btn.dataset.url, '_blank');
    } else if (btn.classList.contains('btn-icon--delete')) {
      removeFromHistory(btn.dataset.url);
    }
  });

  clearHistoryBtn.addEventListener('click', clearHistory);

  function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  function escapeAttr(str) {
    return str.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // Render on load
  renderHistory();

})();
