(() => {
  // === Clerk auth state ===
  let clerkInstance = null;
  let currentUser = null; // { clerkId, email, isPro, proExpiresAt, ... }

  const proBadge = document.getElementById('proBadge');
  const goProBtn = document.getElementById('goProBtn');
  const goProBtn2 = document.getElementById('goProBtn2');
  const goProBtn3 = document.getElementById('goProBtn3');
  const manageBtn = document.getElementById('manageBtn');
  const dashBtn = document.getElementById('dashBtn');
  const authUser = document.getElementById('authUser');
  const authAvatar = document.getElementById('authAvatar');
  const signOutBtn = document.getElementById('signOutBtn');
  const signInBtn = document.getElementById('signInBtn');
  const signUpFreeBtn = document.getElementById('signUpFreeBtn');

  const proUpsell = document.getElementById('proUpsell');
  const proFields = document.getElementById('proFields');
  const slugInput = document.getElementById('slugInput');
  const slugHint = document.getElementById('slugHint');
  const expirationSelect = document.getElementById('expirationSelect');
  const viewCapInput = document.getElementById('viewCapInput');
  const isPublicInput = document.getElementById('isPublicInput');
  const uploadTagline = document.getElementById('uploadTagline');

  async function initClerk() {
    const scriptTag = document.getElementById('clerk-script');
    const publishableKey = scriptTag?.getAttribute('data-clerk-publishable-key');
    if (!publishableKey) return; // Clerk not configured (dev/local)

    await new Promise((resolve) => {
      if (window.Clerk) return resolve();
      scriptTag.addEventListener('load', resolve);
    });

    clerkInstance = window.Clerk;
    await clerkInstance.load();

    clerkInstance.addListener(handleAuthChange);
    handleAuthChange();
  }

  async function handleAuthChange() {
    const user = clerkInstance?.user;

    if (user) {
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

      signInBtn?.classList.add('hidden');
      authUser?.classList.remove('hidden');
      if (authAvatar) authAvatar.src = user.imageUrl || '';
      dashBtn?.classList.remove('hidden');

      const isPro = !!currentUser?.isPro;
      proBadge?.classList.toggle('hidden', !isPro);
      goProBtn?.classList.toggle('hidden', isPro);
      manageBtn?.classList.toggle('hidden', !isPro);
      proFields?.classList.toggle('hidden', !isPro);
      proUpsell?.classList.add('hidden');
      updateUploadTagline();
    } else {
      currentUser = null;
      signInBtn?.classList.remove('hidden');
      authUser?.classList.add('hidden');
      proBadge?.classList.add('hidden');
      goProBtn?.classList.add('hidden');
      manageBtn?.classList.add('hidden');
      dashBtn?.classList.add('hidden');
      proFields?.classList.add('hidden');
      proUpsell?.classList.add('hidden');
      updateUploadTagline();
    }
  }

  function updateUploadTagline() {
    if (!uploadTagline) return;
    if (!currentUser) {
      uploadTagline.textContent = 'No account needed · Anonymous links last 1 day · 300 views.';
    } else if (currentUser.isPro) {
      uploadTagline.textContent = 'Pro · Custom URL, expiry up to forever, edit-in-place.';
    } else {
      uploadTagline.textContent = 'Free account · 3 active links · 7-day expiry · 1,000 views.';
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

  signInBtn?.addEventListener('click', () => clerkInstance?.openSignIn());
  signOutBtn?.addEventListener('click', () => clerkInstance?.signOut());
  signUpFreeBtn?.addEventListener('click', () => clerkInstance?.openSignIn());
  goProBtn?.addEventListener('click', startCheckout);
  goProBtn2?.addEventListener('click', startCheckout);
  goProBtn3?.addEventListener('click', startCheckout);
  manageBtn?.addEventListener('click', openBillingPortal);

  initClerk();

  // === Rotating noun in the hero ===
  // Same animation as the Phase 7 prototype: ghost word reserves the
  // widest width so the layout doesn't jump; current word slides up + out
  // while the next word slides up + in.
  const ROTATING_WORDS = [
    'a website',
    'an itinerary',
    'a dashboard',
    'an invite',
    'a resume',
    'a menu',
    'a pitch deck',
    'a one-pager',
    'a landing page',
  ];
  const rotEl = document.getElementById('rotatingNoun');
  if (rotEl) {
    const widest = ROTATING_WORDS.reduce((a, b) => (b.length > a.length ? b : a), '');
    rotEl.classList.add('rb-rotwrap');
    rotEl.innerHTML = `
      <span class="rb-rotghost">${widest}</span>
      <span class="rb-rotclip" id="rotatingClip">
        <span class="rb-rotword in">${ROTATING_WORDS[0]}</span>
      </span>
    `;
    const clip = document.getElementById('rotatingClip');
    let i = 0;
    setInterval(() => {
      const prev = i;
      i = (i + 1) % ROTATING_WORDS.length;
      clip.innerHTML =
        `<span class="rb-rotword out">${ROTATING_WORDS[prev]}</span>` +
        `<span class="rb-rotword in">${ROTATING_WORDS[i]}</span>`;
    }, 2400);
  }

  // === Upload elements ===
  const uploadCard = document.getElementById('uploadCard');
  const uploadSection = document.getElementById('uploadSection');
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const fileInfo = document.getElementById('fileInfo');
  const previewSection = document.getElementById('previewSection');
  const previewFrame = document.getElementById('previewFrame');
  const previewFilename = document.getElementById('previewFilename');
  const removeFileBtn = document.getElementById('removeFile');
  const passwordSection = document.getElementById('passwordSection');
  const passwordInput = document.getElementById('passwordInput');
  const confirmPasswordInput = document.getElementById('confirmPasswordInput');
  const confirmHint = document.getElementById('confirmHint');
  const generateBtn = document.getElementById('generateBtn');
  const generateBtnLabel = document.getElementById('generateBtnLabel');
  const resultSection = document.getElementById('resultSection');
  const linkOutput = document.getElementById('linkOutput');
  const copyBtn = document.getElementById('copyBtn');
  const expirationNote = document.getElementById('expirationNote');
  const resetBtn = document.getElementById('resetBtn');
  const cardStep = document.getElementById('cardStep');

  const pasteSection = document.getElementById('pasteSection');
  const pasteInput = document.getElementById('pasteInput');
  const pasteToggleBtn = document.getElementById('pasteToggleBtn');
  const pasteCancelBtn = document.getElementById('pasteCancelBtn');
  const pasteUseBtn = document.getElementById('pasteUseBtn');

  // Tier 1 file size cap. Mirror of server/tiers.js — keep these in sync.
  const MAX_SIZE = 10 * 1024 * 1024;

  let currentFile = null;

  // === Drag and drop ===
  dropzone?.addEventListener('click', () => fileInput.click());
  dropzone?.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });
  dropzone?.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
  dropzone?.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer?.files?.length) handleFile(e.dataTransfer.files[0]);
  });
  fileInput?.addEventListener('change', () => {
    if (fileInput.files.length > 0) handleFile(fileInput.files[0]);
  });

  // === Paste HTML toggle ===
  pasteToggleBtn?.addEventListener('click', () => {
    if (!dropzone) return;
    dropzone.style.display = 'none';
    pasteToggleBtn.classList.add('hidden');
    pasteSection.classList.remove('hidden');
    pasteInput.focus();
  });
  pasteCancelBtn?.addEventListener('click', () => {
    pasteSection.classList.add('hidden');
    pasteInput.value = '';
    if (dropzone) dropzone.style.display = '';
    pasteToggleBtn.classList.remove('hidden');
  });
  pasteUseBtn?.addEventListener('click', () => {
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
    const ext = (file.name.split('.').pop() || '').toLowerCase();
    if (ext !== 'html' && ext !== 'htm') {
      fileInfo.textContent = 'Only .html and .htm files are accepted.';
      return;
    }
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
      previewFrame.srcdoc = html;
      if (previewFilename) previewFilename.textContent = file.name;
      uploadSection?.classList.add('hidden');
      previewSection.classList.remove('hidden');
      passwordSection.classList.remove('hidden');
      resultSection.classList.add('hidden');
      if (cardStep) cardStep.textContent = '02 / Set a password';
      fileInfo.textContent = '';
      setTimeout(() => passwordInput.focus(), 200);
    };
    reader.readAsText(file);
  }

  // === Reset / remove ===
  removeFileBtn?.addEventListener('click', resetAll);
  resetBtn?.addEventListener('click', resetAll);

  function resetAll() {
    currentFile = null;
    fileInput.value = '';
    passwordInput.value = '';
    if (confirmPasswordInput) confirmPasswordInput.value = '';
    if (confirmHint) { confirmHint.textContent = ''; confirmHint.className = 'field-hint'; }
    if (slugInput) slugInput.value = '';
    if (slugHint) { slugHint.textContent = ''; slugHint.className = 'field-hint'; }
    if (expirationSelect) expirationSelect.value = '30';
    if (viewCapInput) viewCapInput.value = '';
    if (isPublicInput) {
      isPublicInput.checked = false;
      applyPublicToggle();
    }
    fileInfo.textContent = '';
    previewFrame.srcdoc = '';
    uploadSection?.classList.remove('hidden');
    if (dropzone) dropzone.style.display = '';
    previewSection.classList.add('hidden');
    passwordSection.classList.add('hidden');
    resultSection.classList.add('hidden');
    proUpsell?.classList.add('hidden');
    copyBtn.textContent = 'Copy';
    copyBtn.classList.remove('copied');
    pasteSection.classList.add('hidden');
    pasteInput.value = '';
    pasteToggleBtn.classList.remove('hidden');
    if (cardStep) cardStep.textContent = 'Easy mode';
  }

  // === Generate link ===
  generateBtn?.addEventListener('click', async () => {
    const password = passwordInput.value.trim();
    const confirmPassword = confirmPasswordInput?.value.trim();
    const wantsPublic = !!(currentUser?.isPro && isPublicInput?.checked);

    // Public Pro pages skip the password gate; everyone else needs one.
    if (!wantsPublic && !password) {
      passwordInput.style.borderColor = 'var(--rb-error)';
      passwordInput.focus();
      return;
    }
    if (!wantsPublic && confirmPasswordInput && password !== confirmPassword) {
      confirmPasswordInput.style.borderColor = 'var(--rb-error)';
      if (confirmHint) {
        confirmHint.textContent = 'Passwords don’t match.';
        confirmHint.className = 'field-hint field-hint--error';
      }
      confirmPasswordInput.focus();
      return;
    }
    passwordInput.style.borderColor = '';
    if (confirmPasswordInput) confirmPasswordInput.style.borderColor = '';
    fileInfo.textContent = '';

    generateBtn.disabled = true;
    if (generateBtnLabel) generateBtnLabel.textContent = 'Sealing…';

    try {
      const formData = new FormData();
      formData.append('file', currentFile);
      formData.append('password', password);
      if (confirmPassword !== undefined) formData.append('confirmPassword', confirmPassword);
      if (wantsPublic) formData.append('isPublic', 'true');

      if (currentUser?.isPro) {
        const slug = slugInput?.value.trim().toLowerCase();
        if (slug) formData.append('slug', slug);
        const expiration = expirationSelect?.value;
        if (expiration) formData.append('expiration', expiration);
        const viewCap = viewCapInput?.value.trim();
        if (viewCap) formData.append('viewCap', viewCap);
      }

      const headers = {};
      if (clerkInstance?.session) {
        const token = await clerkInstance.session.getToken();
        if (token) headers['Authorization'] = `Bearer ${token}`;
      }

      const res = await fetch('/api/upload', { method: 'POST', body: formData, headers });
      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        fileInfo.textContent = data.error || 'Upload failed';
        return;
      }

      const expDate = new Date(data.expiresAt);
      linkOutput.value = data.url;
      if (expDate.getFullYear() >= 9999) {
        expirationNote.textContent = 'Password-locked · never expires.';
      } else {
        const expStr = expDate.toLocaleDateString('en-US', {
          month: 'long',
          day: 'numeric',
          year: 'numeric',
        });
        expirationNote.textContent = `Password-locked · expires ${expStr}.`;
      }
      previewSection.classList.add('hidden');
      passwordSection.classList.add('hidden');
      uploadSection?.classList.add('hidden');
      resultSection.classList.remove('hidden');
      if (cardStep) cardStep.textContent = 'Sealed';

      if (window.plausible) {
        plausible('Upload', { props: { filename: currentFile.name, size: currentFile.size } });
      }

      // Show the Pro upsell once a link has been created (signed-in non-Pro only).
      if (clerkInstance && currentUser && !currentUser.isPro) {
        proUpsell?.classList.remove('hidden');
      }

      resultSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
    } catch {
      fileInfo.textContent = 'Upload failed. Please try again.';
    } finally {
      generateBtn.disabled = false;
      if (generateBtnLabel) generateBtnLabel.textContent = 'Generate link';
    }
  });

  passwordInput?.addEventListener('input', () => {
    passwordInput.style.borderColor = '';
    if (confirmHint && confirmHint.textContent) {
      confirmHint.textContent = '';
      confirmHint.className = 'field-hint';
    }
    if (confirmPasswordInput) confirmPasswordInput.style.borderColor = '';
  });
  passwordInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') generateBtn.click();
  });
  confirmPasswordInput?.addEventListener('input', () => {
    confirmPasswordInput.style.borderColor = '';
    if (confirmHint) { confirmHint.textContent = ''; confirmHint.className = 'field-hint'; }
  });
  confirmPasswordInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') generateBtn.click();
  });

  // === Copy link ===
  copyBtn?.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(linkOutput.value);
      copyBtn.textContent = 'Copied!';
      copyBtn.classList.add('copied');
      setTimeout(() => {
        copyBtn.textContent = 'Copy';
        copyBtn.classList.remove('copied');
      }, 1500);
    } catch {
      linkOutput.select();
      try { document.execCommand('copy'); } catch { /* ignore */ }
    }
  });

  // === Public-page toggle ===
  // Hides the password+confirm inputs entirely. The server enforces the
  // same rule; this is just so the form doesn't ask for something that
  // won't be used.
  function applyPublicToggle() {
    const publicMode = !!isPublicInput?.checked;
    const passwordGroup = passwordInput?.closest('.input-group');
    const confirmGroup = confirmPasswordInput?.closest('.input-group');
    if (passwordGroup) passwordGroup.classList.toggle('hidden', publicMode);
    if (confirmGroup) confirmGroup.classList.toggle('hidden', publicMode);
    if (publicMode) {
      passwordInput.value = '';
      if (confirmPasswordInput) confirmPasswordInput.value = '';
    }
  }
  isPublicInput?.addEventListener('change', applyPublicToggle);

  // === Slug validation — keep in sync with tiers.PRO_SLUG_REGEX. ===
  // Spec: 3+ hyphenated word groups, each ≥ 2 chars, lowercase alphanumeric,
  // total ≤ 60 chars. Example: "my-landing-page".
  const PRO_SLUG_REGEX = /^[a-z0-9]{2,}(-[a-z0-9]{2,}){2,}$/;
  const PRO_SLUG_MAX_LEN = 60;
  slugInput?.addEventListener('input', () => {
    const val = slugInput.value.trim().toLowerCase();
    if (!val) { slugHint.textContent = ''; slugHint.className = 'field-hint'; return; }
    if (val.length > PRO_SLUG_MAX_LEN) {
      slugHint.textContent = `Keep it under ${PRO_SLUG_MAX_LEN} characters.`;
      slugHint.className = 'field-hint field-hint--error';
    } else if (!PRO_SLUG_REGEX.test(val)) {
      slugHint.textContent = 'Use 3+ hyphenated word groups, each at least 2 characters (e.g. my-landing-page).';
      slugHint.className = 'field-hint field-hint--error';
    } else {
      slugHint.textContent = 'Looks good.';
      slugHint.className = 'field-hint field-hint--ok';
    }
  });

  // Stale localStorage from the old in-page "My Pages" history (removed in
  // Phase 2). Best-effort cleanup so users don't carry around abandoned data.
  try { localStorage.removeItem('pagegate_history'); } catch { /* ignore */ }
})();
