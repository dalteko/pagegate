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

  const MAX_SIZE = 5 * 1024 * 1024; // 5MB
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


})();
