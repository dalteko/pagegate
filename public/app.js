(() => {
  // === Clerk Auth State ===
  let clerkInstance = null;
  let currentUser = null; // { clerkId, email, isPro, proExpiresAt }

  const authNav = document.getElementById('authNav');
  const proBadge = document.getElementById('proBadge');
  const goProBtn = document.getElementById('goProBtn');
  const goProBtn2 = document.getElementById('goProBtn2');
  const manageBtn = document.getElementById('manageBtn');
  const authUser = document.getElementById('authUser');
  const authAvatar = document.getElementById('authAvatar');
  const signOutBtn = document.getElementById('signOutBtn');
  const signInBtn = document.getElementById('signInBtn');
  const proUpsell = document.getElementById('proUpsell');
  const proFields = document.getElementById('proFields');
  const slugInput = document.getElementById('slugInput');
  const slugHint = document.getElementById('slugHint');
  const expirationSelect = document.getElementById('expirationSelect');
  const dashBtn = document.getElementById('dashBtn');

  async function initClerk() {
    const scriptTag = document.getElementById('clerk-script');
    const publishableKey = scriptTag?.getAttribute('data-clerk-publishable-key');
    if (!publishableKey) return; // Clerk not configured

    // Wait for Clerk to load
    await new Promise((resolve) => {
      if (window.Clerk) return resolve();
      scriptTag.addEventListener('load', resolve);
    });

    clerkInstance = window.Clerk;
    await clerkInstance.load();

    authNav.classList.remove('hidden');

    clerkInstance.addListener(handleAuthChange);
    handleAuthChange();
  }

  async function handleAuthChange() {
    const user = clerkInstance?.user;

    if (user) {
      // Sync user to our DB
      try {
        const token = await clerkInstance.session.getToken();
        const res = await fetch('/api/auth/sync', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
          },
          body: JSON.stringify({ email: user.primaryEmailAddress?.emailAddress }),
        });
        if (res.ok) {
          currentUser = await res.json();
        }
      } catch (e) {
        console.error('Auth sync failed:', e);
      }

      // Update UI
      signInBtn.classList.add('hidden');
      authUser.classList.remove('hidden');
      authAvatar.src = user.imageUrl || '';

      // Dashboard link is available to any signed-in user (Tier 2 + Tier 3).
      // Pro-specific UI (slug/expiration fields, manage billing, no upsell)
      // gates separately on isPro.
      dashBtn.classList.remove('hidden');
      if (currentUser?.isPro) {
        proBadge.classList.remove('hidden');
        goProBtn.classList.add('hidden');
        manageBtn.classList.remove('hidden');
        proFields?.classList.remove('hidden');
        proUpsell.classList.add('hidden');
      } else {
        proBadge.classList.add('hidden');
        goProBtn.classList.remove('hidden');
        manageBtn.classList.add('hidden');
        proFields?.classList.add('hidden');
      }
    } else {
      // Signed out
      currentUser = null;
      signInBtn.classList.remove('hidden');
      authUser.classList.add('hidden');
      proBadge.classList.add('hidden');
      goProBtn.classList.add('hidden');
      manageBtn.classList.add('hidden');
      dashBtn.classList.add('hidden');
      proFields?.classList.add('hidden');
      proUpsell.classList.add('hidden');
    }
  }

  async function startCheckout() {
    if (!clerkInstance?.user) {
      clerkInstance?.openSignIn();
      return;
    }
    try {
      const token = await clerkInstance.session.getToken();
      const res = await fetch('/api/checkout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
      });
      const data = await res.json();
      if (data.url) window.location.href = data.url;
    } catch (e) {
      console.error('Checkout failed:', e);
    }
  }

  async function openBillingPortal() {
    try {
      const token = await clerkInstance.session.getToken();
      const res = await fetch('/api/billing-portal', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
      });
      const data = await res.json();
      if (data.url) window.location.href = data.url;
    } catch (e) {
      console.error('Billing portal failed:', e);
    }
  }

  // Auth event listeners
  signInBtn?.addEventListener('click', () => clerkInstance?.openSignIn());
  signOutBtn?.addEventListener('click', () => clerkInstance?.signOut());
  goProBtn?.addEventListener('click', startCheckout);
  goProBtn2?.addEventListener('click', startCheckout);
  manageBtn?.addEventListener('click', openBillingPortal);

  // Initialize Clerk
  initClerk();

  // Elements
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const fileInfo = document.getElementById('fileInfo');
  const previewSection = document.getElementById('previewSection');
  const previewFrame = document.getElementById('previewFrame');
  const removeFileBtn = document.getElementById('removeFile');
  const passwordSection = document.getElementById('passwordSection');
  const passwordInput = document.getElementById('passwordInput');
  const confirmPasswordInput = document.getElementById('confirmPasswordInput');
  const confirmHint = document.getElementById('confirmHint');
  const generateBtn = document.getElementById('generateBtn');
  const resultSection = document.getElementById('resultSection');
  const linkOutput = document.getElementById('linkOutput');
  const copyBtn = document.getElementById('copyBtn');
  const expirationNote = document.getElementById('expirationNote');
  const resetBtn = document.getElementById('resetBtn');

  // Tier 1 file size cap. Mirror of server/tiers.js — keep these in sync.
  const MAX_SIZE = 10 * 1024 * 1024; // 10 MB

  const pasteSection = document.getElementById('pasteSection');
  const pasteInput = document.getElementById('pasteInput');
  const pasteToggleBtn = document.getElementById('pasteToggleBtn');
  const pasteCancelBtn = document.getElementById('pasteCancelBtn');
  const pasteUseBtn = document.getElementById('pasteUseBtn');

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

  // === Paste HTML toggle ===
  pasteToggleBtn.addEventListener('click', () => {
    dropzone.style.display = 'none';
    pasteToggleBtn.classList.add('hidden');
    pasteSection.classList.remove('hidden');
    pasteInput.focus();
  });

  pasteCancelBtn.addEventListener('click', () => {
    pasteSection.classList.add('hidden');
    pasteInput.value = '';
    dropzone.style.display = '';
    pasteToggleBtn.classList.remove('hidden');
  });

  pasteUseBtn.addEventListener('click', () => {
    const html = pasteInput.value.trim();
    if (!html) {
      fileInfo.textContent = 'Paste some HTML code first.';
      return;
    }
    const file = new File([html], 'pasted.html', { type: 'text/html' });
    pasteSection.classList.add('hidden');
    pasteToggleBtn.classList.add('hidden');
    handleFile(file);
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
      fileInfo.textContent = 'File must be under 10 MB.';
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
    const confirmPassword = confirmPasswordInput?.value.trim();
    if (!password) {
      passwordInput.style.borderColor = '#EF4444';
      passwordInput.focus();
      return;
    }
    // Confirm-password is required for anonymous uploads since there's no
    // recovery — a typo would create a dead page. We always require it
    // client-side regardless of tier; the server enforces the same rule.
    if (confirmPasswordInput && password !== confirmPassword) {
      confirmPasswordInput.style.borderColor = '#EF4444';
      if (confirmHint) {
        confirmHint.textContent = 'Passwords do not match';
        confirmHint.className = 'field-hint field-hint--error';
      }
      confirmPasswordInput.focus();
      return;
    }
    passwordInput.style.borderColor = '';
    if (confirmPasswordInput) confirmPasswordInput.style.borderColor = '';
    fileInfo.textContent = '';

    generateBtn.disabled = true;
    generateBtn.textContent = 'Uploading...';

    try {
      const formData = new FormData();
      formData.append('file', currentFile);
      formData.append('password', password);
      if (confirmPassword !== undefined) formData.append('confirmPassword', confirmPassword);

      // Add Pro fields if available
      if (currentUser?.isPro) {
        const slug = slugInput?.value.trim().toLowerCase();
        if (slug) formData.append('slug', slug);
        const expiration = expirationSelect?.value;
        if (expiration) formData.append('expiration', expiration);
      }

      // Include auth header if signed in
      const headers = {};
      if (clerkInstance?.session) {
        const token = await clerkInstance.session.getToken();
        if (token) headers['Authorization'] = `Bearer ${token}`;
      }

      const res = await fetch('/api/upload', { method: 'POST', body: formData, headers });
      const data = await res.json();

      if (!res.ok) {
        fileInfo.textContent = data.error || 'Upload failed';
        return;
      }

      // Format expiration date
      const expDate = new Date(data.expiresAt);
      linkOutput.value = data.url;
      if (expDate.getFullYear() >= 9999) {
        expirationNote.textContent = 'Never expires';
      } else {
        const expStr = expDate.toLocaleDateString('en-US', {
          month: 'long',
          day: 'numeric',
          year: 'numeric',
        });
        expirationNote.textContent = `Expires ${expStr}`;
      }
      resultSection.classList.remove('hidden');
      passwordSection.classList.add('hidden');

      // Track upload in Plausible
      if (window.plausible) plausible('Upload', { props: { filename: currentFile.name, size: currentFile.size } });

      // Per the tier-1 spec: no client-side history. The link is shown once
      // here in the result card, then dismissed. Logged-in users will see
      // their pages in the server-side dashboard added in Phase 3.

      // Show Pro upsell for non-Pro users after upload
      if (clerkInstance && !currentUser?.isPro) {
        proUpsell.classList.remove('hidden');
      }

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
    if (confirmPasswordInput) confirmPasswordInput.value = '';
    if (confirmHint) { confirmHint.textContent = ''; confirmHint.className = 'field-hint'; }
    if (slugInput) slugInput.value = '';
    if (slugHint) { slugHint.textContent = ''; slugHint.className = 'field-hint'; }
    if (expirationSelect) expirationSelect.value = '30';
    fileInfo.textContent = '';
    previewFrame.srcdoc = '';
    dropzone.style.display = '';
    previewSection.classList.add('hidden');
    passwordSection.classList.add('hidden');
    resultSection.classList.add('hidden');
    proUpsell.classList.add('hidden');
    copyBtn.textContent = 'Copy';
    copyBtn.classList.remove('copied');
    pasteSection.classList.add('hidden');
    pasteInput.value = '';
    pasteToggleBtn.classList.remove('hidden');
  }

  // Clear the mismatch hint as soon as the user edits either field.
  confirmPasswordInput?.addEventListener('input', () => {
    confirmPasswordInput.style.borderColor = '';
    if (confirmHint) { confirmHint.textContent = ''; confirmHint.className = 'field-hint'; }
  });
  passwordInput?.addEventListener('input', () => {
    if (confirmHint && confirmHint.textContent) {
      confirmHint.textContent = '';
      confirmHint.className = 'field-hint';
    }
    if (confirmPasswordInput) confirmPasswordInput.style.borderColor = '';
  });

  // Slug validation on input
  slugInput?.addEventListener('input', () => {
    const val = slugInput.value.trim().toLowerCase();
    if (!val) { slugHint.textContent = ''; slugHint.className = 'field-hint'; return; }
    if (val.length < 3) {
      slugHint.textContent = 'At least 3 characters';
      slugHint.className = 'field-hint field-hint--error';
    } else if (!/^[a-z0-9][a-z0-9-]*[a-z0-9]$/.test(val)) {
      slugHint.textContent = 'Lowercase letters, numbers, and hyphens only';
      slugHint.className = 'field-hint field-hint--error';
    } else {
      slugHint.textContent = '';
      slugHint.className = 'field-hint';
    }
  });

  // Stale localStorage from the old in-page "My Pages" history (removed in
  // Phase 2 — anonymous links per spec are shown once and not recoverable).
  // Best-effort cleanup so users don't carry around abandoned data.
  try { localStorage.removeItem('pagegate_history'); } catch { /* ignore */ }

  // === Feedback (submit only — list is private) ===
  const feedbackInput = document.getElementById('feedbackInput');
  const feedbackSubmitBtn = document.getElementById('feedbackSubmitBtn');
  const feedbackError = document.getElementById('feedbackError');

  feedbackSubmitBtn.addEventListener('click', async () => {
    const text = feedbackInput.value.trim();
    feedbackError.classList.add('hidden');
    if (!text || text.length < 3) {
      feedbackError.textContent = 'Too short';
      feedbackError.classList.remove('hidden');
      return;
    }
    feedbackSubmitBtn.disabled = true;
    try {
      const res = await fetch('/api/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
      });
      if (res.ok) {
        feedbackInput.value = '';
        feedbackSubmitBtn.textContent = 'Sent!';
        setTimeout(() => { feedbackSubmitBtn.textContent = 'Submit'; }, 2000);
      } else {
        const data = await res.json();
        feedbackError.textContent = data.error || 'Failed to submit';
        feedbackError.classList.remove('hidden');
      }
    } catch {
      feedbackError.textContent = 'Connection error';
      feedbackError.classList.remove('hidden');
    } finally {
      feedbackSubmitBtn.disabled = false;
    }
  });

  feedbackInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') feedbackSubmitBtn.click();
  });

})();
