/**
 * ╔═══════════════════════════════════════════════════════════════╗
 * ║              CIPHERCHAT CLIENT                                  ║
 * ║  DH Key Exchange · Typing · Read Receipts · Voice · Files     ║
 * ║  Drag & Drop · Avatars · Pipeline Animation                   ║
 * ╚═══════════════════════════════════════════════════════════════╝
 */

(() => {
  // ══════════════════════════════════════════════════════════════
  //  STATE
  // ══════════════════════════════════════════════════════════════
  let socket = null;
  let currentSession = null;
  let nickname = '';
  let myColor = '';

  // DH Key Exchange
  let myKeyPair = null;
  let sharedKeys = null; // { aesKey, hmacKey }
  let isSecureMode = false;

  // Typing indicator
  let typingTimeout = null;
  let isTyping = false;
  const typingUsers = new Map();

  // Read receipts
  const sentMessages = new Map(); // messageId → DOM element

  // Voice recording
  let mediaRecorder = null;
  let audioChunks = [];
  let recordingStartTime = 0;
  let recordingTimer = null;
  let isRecording = false;

  // Pipeline animation
  let animationMode = 'instant'; // 'instant' or 'animated'

  // ══════════════════════════════════════════════════════════════
  //  DOM ELEMENTS
  // ══════════════════════════════════════════════════════════════
  const lobbyScreen = document.getElementById('lobby-screen');
  const chatScreen = document.getElementById('chat-screen');
  const nicknameInput = document.getElementById('nickname-input');
  const sessionIdInput = document.getElementById('session-id-input');
  const createBtn = document.getElementById('create-btn');
  const joinBtn = document.getElementById('join-btn');
  const leaveBtn = document.getElementById('leave-btn');
  const sessionBadge = document.getElementById('session-badge-id');
  const userCountEl = document.getElementById('user-count');
  const messagesContainer = document.getElementById('messages-container');
  const messageInput = document.getElementById('message-input');
  const sendBtn = document.getElementById('send-btn');
  const encStatus = document.getElementById('encryption-status-text');
  const typingIndicator = document.getElementById('typing-indicator');
  const typingNames = document.getElementById('typing-names');

  // Sidebar canvases
  const canvasMessage = document.getElementById('canvas-message');
  const canvasKey = document.getElementById('canvas-key');
  const canvasCipher = document.getElementById('canvas-cipher');
  const canvasDecrypted = document.getElementById('canvas-decrypted');

  // ══════════════════════════════════════════════════════════════
  //  AVATAR GENERATION
  // ══════════════════════════════════════════════════════════════

  function generateAvatarColor(name) {
    let hash = 0;
    for (let i = 0; i < name.length; i++) {
      hash = name.charCodeAt(i) + ((hash << 5) - hash);
      hash = hash & hash;
    }
    const hue = Math.abs(hash % 360);
    return `hsl(${hue}, 70%, 60%)`;
  }

  function getInitial(name) {
    return name.charAt(0).toUpperCase();
  }

  function avatarHTML(name, color, size = 'sm') {
    const c = color || generateAvatarColor(name);
    const initial = getInitial(name);
    return `<div class="avatar avatar-${size}" style="background:${c}" title="${escapeHtml(name)}">${initial}</div>`;
  }

  // ══════════════════════════════════════════════════════════════
  //  SOCKET INITIALIZATION
  // ══════════════════════════════════════════════════════════════

  function initSocket() {
    socket = io();

    socket.on('connect', () => {
      console.log('🔌 Connected to server');
    });

    socket.on('encrypted-message', (payload) => {
      handleIncomingMessage(payload);
    });

    socket.on('session-update', (info) => {
      if (info) {
        userCountEl.textContent = `${info.userCount} user${info.userCount !== 1 ? 's' : ''} online`;
        sessionBadge.textContent = info.sessionId;

        // Update user tooltip list with avatars
        const tooltipList = document.getElementById('user-tooltip-list');
        if (tooltipList && info.userDetails) {
          tooltipList.innerHTML = info.userDetails.map(u =>
            `<li>${avatarHTML(u.nickname, u.color, 'xs')} ${escapeHtml(u.nickname)}</li>`
          ).join('');
        } else if (tooltipList && info.users) {
          tooltipList.innerHTML = info.users.map(name =>
            `<li>${avatarHTML(name, null, 'xs')} ${escapeHtml(name)}</li>`
          ).join('');
        }
      }
    });

    socket.on('system-message', (msg) => {
      appendSystemMessage(msg.text);
    });

    // DH Key Exchange: receive peer's public key
    socket.on('dh-public-key', async (payload) => {
      if (!myKeyPair) return;
      try {
        sharedKeys = await ImageCrypto.deriveSharedKeys(myKeyPair.privateKey, payload.publicKey);
        isSecureMode = true;
        encStatus.textContent = 'E2E encrypted (DH + AES-256 + HMAC)';
        appendSystemMessage(`🔐 Secure channel established with ${payload.senderName}`);
        console.log('🔑 DH shared keys derived with', payload.senderName);
      } catch (err) {
        console.warn('DH key exchange failed:', err);
      }
    });

    // When a new peer joins, rebroadcast our DH public key
    socket.on('peer-joined', ({ peerId, peerName }) => {
      if (myKeyPair) {
        console.log(`👋 ${peerName} joined, rebroadcasting DH key`);
        socket.emit('dh-public-key', { publicKey: myKeyPair.publicKey });
      }
    });

    // Message sent confirmation with ID
    socket.on('message-sent', ({ messageId, timestamp }) => {
      // Update the last sent message with messageId for read receipts
      const lastSent = messagesContainer.querySelector('.message.sent:last-child');
      if (lastSent) {
        lastSent.dataset.messageId = messageId;
        sentMessages.set(messageId, lastSent);
        updateReceipt(lastSent, 'sent');
      }
    });

    // Read receipts
    socket.on('message-read', ({ messageId }) => {
      const msgEl = sentMessages.get(messageId);
      if (msgEl) {
        updateReceipt(msgEl, 'read');
      }
    });

    // Typing indicators
    socket.on('typing', ({ senderName }) => {
      typingUsers.set(senderName, Date.now());
      updateTypingIndicator();
    });

    socket.on('stop-typing', ({ senderName }) => {
      typingUsers.delete(senderName);
      updateTypingIndicator();
    });

    socket.on('disconnect', () => {
      console.log('🔌 Disconnected');
      isSecureMode = false;
      sharedKeys = null;
    });
  }

  // ══════════════════════════════════════════════════════════════
  //  TYPING INDICATOR
  // ══════════════════════════════════════════════════════════════

  function emitTyping() {
    if (!currentSession) return;
    if (!isTyping) {
      isTyping = true;
      socket.emit('typing');
    }
    clearTimeout(typingTimeout);
    typingTimeout = setTimeout(() => {
      isTyping = false;
      socket.emit('stop-typing');
    }, 1500);
  }

  function updateTypingIndicator() {
    if (!typingIndicator) return;
    // Clear stale entries (>3s old)
    const now = Date.now();
    typingUsers.forEach((ts, name) => {
      if (now - ts > 3000) typingUsers.delete(name);
    });

    if (typingUsers.size === 0) {
      typingIndicator.classList.remove('active');
      return;
    }

    const names = Array.from(typingUsers.keys());
    let text;
    if (names.length === 1) text = `${names[0]} is typing`;
    else if (names.length === 2) text = `${names[0]} and ${names[1]} are typing`;
    else text = `${names.length} people are typing`;

    if (typingNames) typingNames.textContent = text;
    typingIndicator.classList.add('active');
  }

  // ══════════════════════════════════════════════════════════════
  //  READ RECEIPTS
  // ══════════════════════════════════════════════════════════════

  function updateReceipt(msgEl, status) {
    const receiptEl = msgEl.querySelector('.message-receipt');
    if (!receiptEl) return;
    if (status === 'sent') {
      receiptEl.innerHTML = '<span class="receipt-check">✓</span>';
      receiptEl.classList.remove('read');
    } else if (status === 'read') {
      receiptEl.innerHTML = '<span class="receipt-check read">✓✓</span>';
      receiptEl.classList.add('read');
    }
  }

  function markAsRead(payload) {
    if (payload.senderId && payload.messageId) {
      socket.emit('message-read', {
        messageId: payload.messageId,
        senderId: payload.senderId
      });
    }
  }

  // ══════════════════════════════════════════════════════════════
  //  SESSION MANAGEMENT
  // ══════════════════════════════════════════════════════════════

  async function createSession() {
    nickname = nicknameInput.value.trim();
    if (!nickname) { shakeElement(nicknameInput); nicknameInput.focus(); return; }
    myColor = generateAvatarColor(nickname);

    // Generate DH key pair if secure context
    if (ImageCrypto.isSecureContext()) {
      try {
        myKeyPair = await ImageCrypto.generateKeyPair();
        console.log('🔑 ECDH key pair generated');
      } catch (err) {
        console.warn('DH keygen failed, falling back to XOR-only:', err);
      }
    }

    socket.emit('create-session', nickname, (response) => {
      if (response.success) {
        currentSession = response.sessionId;
        showChat();
        appendSystemMessage(`Session ${currentSession} created. Share this ID with others!`);

        // Broadcast DH public key
        if (myKeyPair) {
          socket.emit('dh-public-key', { publicKey: myKeyPair.publicKey });
        }
      }
    });
  }

  async function joinSession() {
    nickname = nicknameInput.value.trim();
    const sessionId = sessionIdInput.value.trim().toUpperCase();
    if (!nickname) { shakeElement(nicknameInput); nicknameInput.focus(); return; }
    if (!sessionId) { shakeElement(sessionIdInput); sessionIdInput.focus(); return; }
    myColor = generateAvatarColor(nickname);

    // Generate DH key pair
    if (ImageCrypto.isSecureContext()) {
      try {
        myKeyPair = await ImageCrypto.generateKeyPair();
        console.log('🔑 ECDH key pair generated');
      } catch (err) {
        console.warn('DH keygen failed:', err);
      }
    }

    socket.emit('join-session', { sessionId, nickname }, (response) => {
      if (response.success) {
        currentSession = response.sessionId;
        showChat();
        if (myKeyPair) {
          socket.emit('dh-public-key', { publicKey: myKeyPair.publicKey });
        }
      } else {
        showError(response.error);
      }
    });
  }

  function leaveSession() {
    socket.emit('leave-session');
    currentSession = null;
    myKeyPair = null;
    sharedKeys = null;
    isSecureMode = false;
    showLobby();
  }

  // ══════════════════════════════════════════════════════════════
  //  SEND TEXT MESSAGE
  // ══════════════════════════════════════════════════════════════

  async function sendMessage() {
    const text = messageInput.value.trim();
    if (!text || !currentSession) return;

    encStatus.textContent = 'Encrypting...';

    if (isSecureMode && sharedKeys) {
      const encrypted = await ImageCrypto.encryptSecure(text, sharedKeys.aesKey, sharedKeys.hmacKey);
      socket.emit('encrypted-message', {
        aesCiphertext: encrypted.aesCiphertext,
        iv: encrypted.iv,
        hmac: encrypted.hmac,
        width: encrypted.width,
        height: encrypted.height,
        isSecure: true,
        originalText: '[E2E Encrypted]'
      });
      if (encrypted._pipeline) updateSidebarCanvases(encrypted._pipeline);
    } else {
      const encrypted = ImageCrypto.encrypt(text);
      socket.emit('encrypted-message', {
        cipherData: encrypted.cipherData,
        keyData: encrypted.keyData,
        messageData: encrypted.messageData,
        decryptedData: encrypted.decryptedData,
        width: encrypted.width,
        height: encrypted.height,
        isSecure: false,
        originalText: text
      });
      updateSidebarCanvases(encrypted);
    }

    appendMessage({
      sender: 'You',
      senderColor: myColor,
      text, isSent: true,
      timestamp: Date.now(),
      verified: isSecureMode ? true : null
    });

    messageInput.value = '';
    isTyping = false;
    socket.emit('stop-typing');
    encStatus.textContent = isSecureMode ? 'E2E encrypted (DH + AES-256 + HMAC)' : 'End-to-end image encrypted';
  }

  // ══════════════════════════════════════════════════════════════
  //  SEND IMAGE (file-based encryption for full quality)
  // ══════════════════════════════════════════════════════════════

  const IMAGE_TYPES = ['image/jpeg','image/png','image/gif','image/webp','image/bmp','image/svg+xml','image/tiff','image/avif','image/ico','image/x-icon','image/heic','image/heif'];
  function isImageFile(file) { return IMAGE_TYPES.includes(file.type) || file.type.startsWith('image/'); }

  async function sendImage(file) {
    if (!currentSession) return;
    try {
      encStatus.textContent = 'Encrypting image...';
      const filePixels = await ImageCrypto.loadFileAsPixels(file);

      if (isSecureMode && sharedKeys) {
        const encrypted = await ImageCrypto.encryptSecurePixels(
          filePixels.dataArray, filePixels.width, filePixels.height,
          sharedKeys.aesKey, sharedKeys.hmacKey
        );
        socket.emit('encrypted-message', {
          aesCiphertext: encrypted.aesCiphertext, iv: encrypted.iv, hmac: encrypted.hmac,
          width: encrypted.width, height: encrypted.height,
          isImage: true, isSecure: true,
          fileMeta: { name: file.name, type: file.type, size: file.size },
          originalText: '[E2E Encrypted Image]'
        });
        if (encrypted._pipeline) updateSidebarCanvases(encrypted._pipeline);
      } else {
        const encrypted = ImageCrypto.encryptFile(filePixels.dataArray, filePixels.width, filePixels.height);
        socket.emit('encrypted-message', {
          cipherData: encrypted.cipherData, keyData: encrypted.keyData,
          width: encrypted.width, height: encrypted.height,
          isImage: true, isSecure: false,
          fileMeta: { name: file.name, type: file.type, size: file.size },
          originalText: '[Encrypted Image]'
        });
        updateSidebarCanvases(encrypted);
      }

      const blobUrl = URL.createObjectURL(file);
      appendImageMessage({ sender: 'You', senderColor: myColor, mediaURL: blobUrl, fileName: file.name, fileBlob: file, isSent: true, timestamp: Date.now(), verified: isSecureMode ? true : null });
      encStatus.textContent = isSecureMode ? 'E2E encrypted (DH + AES-256 + HMAC)' : 'End-to-end image encrypted';
    } catch (err) {
      console.error('Image encryption failed:', err);
      showError('Failed to encrypt image');
    }
  }

  // Video and File sending removed as per image-only restriction.

  // Audio analyser for live visualization
  let audioAnalyser = null;
  let analyserAnimFrame = null;

  async function startRecording() {
    if (isRecording) return; // Guard against double-start
    isRecording = true; // Set immediately to prevent re-entry during permission prompt
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      mediaRecorder = new MediaRecorder(stream, { mimeType: 'audio/webm;codecs=opus' });
      audioChunks = [];

      // Set up audio analyser for live waveform
      const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const source = audioCtx.createMediaStreamSource(stream);
      audioAnalyser = audioCtx.createAnalyser();
      audioAnalyser.fftSize = 64;
      source.connect(audioAnalyser);

      mediaRecorder.ondataavailable = (e) => {
        if (e.data.size > 0) audioChunks.push(e.data);
      };

      mediaRecorder.onstop = async () => {
        stream.getTracks().forEach(t => t.stop());
        audioCtx.close();
        cancelAnimationFrame(analyserAnimFrame);
        audioAnalyser = null;
        const audioBlob = new Blob(audioChunks, { type: 'audio/webm;codecs=opus' });
        isRecording = false;
        updateRecordingUI(false);
        await sendVoiceMessage(audioBlob);
      };

      mediaRecorder.start();
      recordingStartTime = Date.now();
      updateRecordingUI(true);
      drawLiveWaveform();

      recordingTimer = setInterval(() => {
        const elapsed = Math.floor((Date.now() - recordingStartTime) / 1000);
        const mins = Math.floor(elapsed / 60).toString().padStart(2, '0');
        const secs = (elapsed % 60).toString().padStart(2, '0');
        const timerEl = document.getElementById('recording-timer');
        if (timerEl) timerEl.textContent = `${mins}:${secs}`;
      }, 100);

    } catch (err) {
      isRecording = false; // Reset on failure
      console.error('Microphone access denied:', err);
      showError('Microphone access required for voice messages');
    }
  }

  function stopRecording() {
    if (mediaRecorder && mediaRecorder.state === 'recording') {
      mediaRecorder.stop();
      clearInterval(recordingTimer);
    } else {
      // If mediaRecorder isn't in recording state, reset manually
      isRecording = false;
      updateRecordingUI(false);
    }
  }

  function drawLiveWaveform() {
    const container = document.getElementById('live-waveform');
    if (!container || !audioAnalyser) return;
    const bars = container.querySelectorAll('.live-bar');
    const dataArray = new Uint8Array(audioAnalyser.frequencyBinCount);

    function animate() {
      if (!audioAnalyser) return;
      audioAnalyser.getByteFrequencyData(dataArray);
      const barCount = bars.length;
      const step = Math.floor(dataArray.length / barCount);
      for (let i = 0; i < barCount; i++) {
        const val = dataArray[i * step] || 0;
        const height = 4 + (val / 255) * 28;
        bars[i].style.height = `${height}px`;
      }
      analyserAnimFrame = requestAnimationFrame(animate);
    }
    animate();
  }

  function updateRecordingUI(recording) {
    const voiceBtn = document.getElementById('voice-btn');
    const inputWrapper = document.querySelector('.chat-input-wrapper');
    const recordingOverlay = document.getElementById('recording-overlay');

    if (recording) {
      if (voiceBtn) voiceBtn.classList.add('recording');
      if (inputWrapper) inputWrapper.classList.add('recording-active');
      if (recordingOverlay) recordingOverlay.classList.add('active');
    } else {
      if (voiceBtn) voiceBtn.classList.remove('recording');
      if (inputWrapper) inputWrapper.classList.remove('recording-active');
      if (recordingOverlay) recordingOverlay.classList.remove('active');
      cancelAnimationFrame(analyserAnimFrame);
      const timerEl = document.getElementById('recording-timer');
      if (timerEl) timerEl.textContent = '00:00';
      // Reset live waveform bars
      const bars = document.querySelectorAll('#live-waveform .live-bar');
      bars.forEach(b => b.style.height = '4px');
    }
  }

  async function sendVoiceMessage(audioBlob) {
    if (!currentSession) return;
    try {
      encStatus.textContent = 'Encrypting voice...';
      const audioPixels = await ImageCrypto.loadAudioAsPixels(audioBlob);

      if (isSecureMode && sharedKeys) {
        const encrypted = await ImageCrypto.encryptSecurePixels(
          audioPixels.dataArray, audioPixels.width, audioPixels.height,
          sharedKeys.aesKey, sharedKeys.hmacKey
        );
        socket.emit('encrypted-message', {
          aesCiphertext: encrypted.aesCiphertext, iv: encrypted.iv, hmac: encrypted.hmac,
          width: encrypted.width, height: encrypted.height,
          isVoice: true, isSecure: true, originalText: '[E2E Encrypted Voice]'
        });
        if (encrypted._pipeline) updateSidebarCanvases(encrypted._pipeline);
      } else {
        const encrypted = ImageCrypto.encryptImage(audioPixels.dataArray, audioPixels.width, audioPixels.height);
        socket.emit('encrypted-message', {
          cipherData: encrypted.cipherData, keyData: encrypted.keyData,
          messageData: encrypted.messageData, decryptedData: encrypted.decryptedData,
          width: encrypted.width, height: encrypted.height,
          isVoice: true, isSecure: false, originalText: '[Encrypted Voice Message]'
        });
        updateSidebarCanvases(encrypted);
      }

      const duration = Math.floor((Date.now() - recordingStartTime) / 1000);
      appendVoiceMessage({ sender: 'You', senderColor: myColor, audioBlob, duration, isSent: true, timestamp: Date.now() });
      encStatus.textContent = isSecureMode ? 'E2E encrypted (DH + AES-256 + HMAC)' : 'End-to-end image encrypted';
    } catch (err) {
      console.error('Voice encryption failed:', err);
      showError('Failed to encrypt voice message');
    }
  }

  // ══════════════════════════════════════════════════════════════
  //  INCOMING MESSAGE HANDLER
  // ══════════════════════════════════════════════════════════════

  async function handleIncomingMessage(payload) {
    encStatus.textContent = 'Decrypting...';

    // If secure, unwrap AES-GCM + verify HMAC to extract the XOR layer
    if (payload.isSecure && sharedKeys) {
      try {
        const secureResult = await ImageCrypto.decryptSecurePixels(
          payload.aesCiphertext, payload.iv, payload.hmac,
          sharedKeys.aesKey, sharedKeys.hmacKey,
          payload.width, payload.height
        );
        // Inject decrypted XOR components back into payload for sub-handlers
        payload.cipherData = secureResult.cipherData;
        payload.keyData = secureResult.keyData;
        payload._verified = secureResult.verified;
      } catch (err) {
        console.error('E2E decryption failed:', err);
        appendMessage({
          sender: payload.senderName, senderColor: payload.senderColor,
          text: '\u26a0\ufe0f [Decryption Failed \u2014 message may be tampered]',
          isSent: false, timestamp: payload.timestamp,
          verified: false, messageId: payload.messageId, senderId: payload.senderId
        });
        encStatus.textContent = 'Decryption failed';
        return;
      }
    }

    const verified = payload.isSecure ? (payload._verified !== undefined ? payload._verified : true) : null;

    if (payload.isVoice) { handleIncomingVoice(payload, verified); return; }
    if (payload.isVideo) { handleIncomingVideo(payload, verified); return; }
    if (payload.isFile) { handleIncomingFile(payload, verified); return; }
    if (payload.isImage) { handleIncomingImage(payload, verified); return; }

    // Text message
    const result = ImageCrypto.decrypt(payload.cipherData, payload.keyData);
    updateSidebarCanvases({
      messageData: result.decryptedData,
      keyData: payload.keyData,
      cipherData: payload.cipherData,
      decryptedData: result.decryptedData
    });

    appendMessage({
      sender: payload.senderName,
      senderColor: payload.senderColor,
      text: result.text,
      isSent: false,
      timestamp: payload.timestamp,
      verified,
      messageId: payload.messageId,
      senderId: payload.senderId
    });

    markAsRead(payload);
    encStatus.textContent = isSecureMode ? 'E2E encrypted (DH + AES-256 + HMAC)' : 'End-to-end image encrypted';
  }

  function handleIncomingImage(payload, verified) {
    const result = ImageCrypto.decryptFile(payload.cipherData, payload.keyData, payload.width, payload.height);
    updateSidebarCanvases({
      messageData: result.decryptedData, keyData: payload.keyData,
      cipherData: payload.cipherData, decryptedData: result.decryptedData,
      width: payload.width, height: payload.height
    });
    const meta = payload.fileMeta || result.file || {};
    const blob = result.file ? new Blob([result.file.blob], { type: meta.type || 'image/png' }) : null;
    const blobUrl = blob ? URL.createObjectURL(blob) : null;
    appendImageMessage({
      sender: payload.senderName, senderColor: payload.senderColor,
      mediaURL: blobUrl, fileName: meta.name || 'image', fileBlob: blob,
      isSent: false, timestamp: payload.timestamp, verified
    });
    markAsRead(payload);
    encStatus.textContent = isSecureMode ? 'E2E encrypted (DH + AES-256 + HMAC)' : 'End-to-end image encrypted';
  }

  function handleIncomingVideo(payload, verified) {
    const result = ImageCrypto.decryptFile(payload.cipherData, payload.keyData, payload.width, payload.height);
    updateSidebarCanvases({
      messageData: result.decryptedData, keyData: payload.keyData,
      cipherData: payload.cipherData, decryptedData: result.decryptedData,
      width: payload.width, height: payload.height
    });
    const meta = payload.fileMeta || result.file || {};
    const blob = result.file ? new Blob([result.file.blob], { type: meta.type || 'video/mp4' }) : null;
    const blobUrl = blob ? URL.createObjectURL(blob) : null;
    appendVideoMessage({
      sender: payload.senderName, senderColor: payload.senderColor,
      mediaURL: blobUrl, fileName: meta.name || 'video', fileType: meta.type || 'video/mp4', fileBlob: blob,
      isSent: false, timestamp: payload.timestamp, verified
    });
    markAsRead(payload);
    encStatus.textContent = isSecureMode ? 'E2E encrypted (DH + AES-256 + HMAC)' : 'End-to-end image encrypted';
  }

  function handleIncomingFile(payload, verified) {
    const result = ImageCrypto.decryptFile(payload.cipherData, payload.keyData, payload.width, payload.height);
    updateSidebarCanvases({
      messageData: result.decryptedData, keyData: payload.keyData,
      cipherData: payload.cipherData, decryptedData: result.decryptedData,
      width: payload.width, height: payload.height
    });
    const meta = payload.fileMeta || result.file;
    const blob = result.file ? result.file.blob : null;
    appendFileMessage({
      sender: payload.senderName, senderColor: payload.senderColor,
      fileName: meta.name, fileSize: meta.size, fileType: meta.type,
      fileBlob: blob,
      isSent: false, timestamp: payload.timestamp, verified
    });
    markAsRead(payload);
    encStatus.textContent = isSecureMode ? 'E2E encrypted (DH + AES-256 + HMAC)' : 'End-to-end image encrypted';
  }

  function handleIncomingVoice(payload, verified) {
    const result = ImageCrypto.decryptImage(payload.cipherData, payload.keyData, payload.width, payload.height);
    updateSidebarCanvases({
      messageData: result.decryptedData, keyData: payload.keyData,
      cipherData: payload.cipherData, decryptedData: result.decryptedData,
      width: payload.width, height: payload.height
    });
    const audioBlob = ImageCrypto.pixelsToAudio(result.decryptedData);
    appendVoiceMessage({
      sender: payload.senderName, senderColor: payload.senderColor,
      audioBlob, duration: 0, isSent: false, timestamp: payload.timestamp, verified
    });
    markAsRead(payload);
    encStatus.textContent = isSecureMode ? 'E2E encrypted (DH + AES-256 + HMAC)' : 'End-to-end image encrypted';
  }

  // ══════════════════════════════════════════════════════════════
  //  SIDEBAR CANVASES
  // ══════════════════════════════════════════════════════════════

  function updateSidebarCanvases(data) {
    const w = data.width || ImageCrypto.CANVAS_WIDTH;
    const h = data.height || ImageCrypto.CANVAS_HEIGHT;

    if (data.messageData) {
      ImageCrypto.renderToCanvas(canvasMessage, data.messageData, w, h);
      flashCanvas(canvasMessage);
    }
    if (data.keyData) {
      ImageCrypto.renderToCanvas(canvasKey, data.keyData, w, h);
      flashCanvas(canvasKey);
    }

    if (animationMode === 'animated' && data.messageData && data.keyData) {
      ImageCrypto.animateXorPipeline(data.messageData, data.keyData, canvasCipher, 2000).then(() => {
        if (data.decryptedData) {
          ImageCrypto.renderToCanvas(canvasDecrypted, data.decryptedData, w, h);
          flashCanvas(canvasDecrypted);
        }
      });
    } else {
      if (data.cipherData) {
        ImageCrypto.renderToCanvas(canvasCipher, data.cipherData, w, h);
        flashCanvas(canvasCipher);
      }
      if (data.decryptedData) {
        ImageCrypto.renderToCanvas(canvasDecrypted, data.decryptedData, w, h);
        flashCanvas(canvasDecrypted);
      }
    }
  }

  function flashCanvas(canvas) {
    canvas.classList.remove('canvas-flash');
    void canvas.offsetWidth;
    canvas.classList.add('canvas-flash');
  }

  // ══════════════════════════════════════════════════════════════
  //  UI HELPERS
  // ══════════════════════════════════════════════════════════════

  function showChat() {
    lobbyScreen.style.display = 'none';
    chatScreen.classList.add('active');
    sessionBadge.textContent = currentSession;
    messageInput.focus();
    messagesContainer.innerHTML = '';
  }

  function showLobby() {
    chatScreen.classList.remove('active');
    lobbyScreen.style.display = 'flex';
    sessionIdInput.value = '';
  }

  function appendMessage({ sender, senderColor, text, isSent, timestamp, verified, messageId, senderId }) {
    const msgEl = document.createElement('div');
    msgEl.classList.add('message', isSent ? 'sent' : 'received');
    if (messageId) msgEl.dataset.messageId = messageId;
    if (senderId) msgEl.dataset.senderId = senderId;

    const time = new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const color = senderColor || generateAvatarColor(sender);
    const verifiedBadge = verified === true ? '<span class="verified-badge" title="HMAC verified">✅</span>' :
      verified === false ? '<span class="verified-badge tampered" title="HMAC verification failed">⚠️</span>' : '';
    const receiptHTML = isSent ? '<span class="message-receipt"><span class="receipt-check">✓</span></span>' : '';

    msgEl.innerHTML = `
      <div class="message-header">
        ${avatarHTML(sender, color, 'sm')}
        <span class="message-sender">${escapeHtml(sender)}</span>
        ${verifiedBadge}
      </div>
      <div class="message-text">${escapeHtml(text)}</div>
      <div class="message-footer">
        <span class="message-time">${time}</span>
        ${receiptHTML}
        <span class="message-encryption-badge">🔐 Image encrypted</span>
      </div>
    `;

    messagesContainer.appendChild(msgEl);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  function appendImageMessage({ sender, senderColor, mediaURL, fileName, fileBlob, isSent, timestamp, verified }) {
    const msgEl = document.createElement('div');
    msgEl.classList.add('message', isSent ? 'sent' : 'received');
    const time = new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const color = senderColor || generateAvatarColor(sender);
    const verifiedBadge = verified === true ? '<span class="verified-badge" title="HMAC verified">✅</span>' :
      verified === false ? '<span class="verified-badge tampered" title="HMAC verification failed">⚠️</span>' : '';
    const receiptHTML = isSent ? '<span class="message-receipt"><span class="receipt-check">✓</span></span>' : '';

    msgEl.innerHTML = `
      <div class="message-header">
        ${avatarHTML(sender, color, 'sm')}
        <span class="message-sender">${escapeHtml(sender)}</span>
        ${verifiedBadge}
      </div>
      <div class="message-media">
        <img src="${mediaURL}" alt="Encrypted image" class="media-preview" />
        <div class="media-actions">
          <button class="media-enlarge-btn" title="Enlarge">🔍</button>
          <button class="media-download-btn" title="Download">⬇️</button>
        </div>
      </div>
      <div class="message-footer">
        <span class="message-time">${time}</span>
        ${receiptHTML}
        <span class="message-encryption-badge">🔐 E2E encrypted</span>
      </div>
    `;

    // Enlarge handler
    const img = msgEl.querySelector('.media-preview');
    const enlargeBtn = msgEl.querySelector('.media-enlarge-btn');
    [img, enlargeBtn].forEach(el => el?.addEventListener('click', () => openLightbox(mediaURL, 'image')));

    // Download handler
    const dlBtn = msgEl.querySelector('.media-download-btn');
    dlBtn?.addEventListener('click', () => downloadBlob(fileBlob || mediaURL, fileName || 'image.png'));

    messagesContainer.appendChild(msgEl);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  function appendVideoMessage({ sender, senderColor, mediaURL, fileName, fileType, fileBlob, isSent, timestamp, verified }) {
    const msgEl = document.createElement('div');
    msgEl.classList.add('message', isSent ? 'sent' : 'received');
    const time = new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const color = senderColor || generateAvatarColor(sender);
    const verifiedBadge = verified === true ? '<span class="verified-badge" title="HMAC verified">✅</span>' :
      verified === false ? '<span class="verified-badge tampered" title="HMAC verification failed">⚠️</span>' : '';
    const receiptHTML = isSent ? '<span class="message-receipt"><span class="receipt-check">✓</span></span>' : '';

    msgEl.innerHTML = `
      <div class="message-header">
        ${avatarHTML(sender, color, 'sm')}
        <span class="message-sender">${escapeHtml(sender)}</span>
        ${verifiedBadge}
      </div>
      <div class="message-media">
        <video src="${mediaURL}" class="media-preview" controls preload="metadata" playsinline></video>
        <div class="media-actions">
          <button class="media-enlarge-btn" title="Enlarge">🔍</button>
          <button class="media-download-btn" title="Download">⬇️</button>
        </div>
      </div>
      <div class="message-footer">
        <span class="message-time">${time}</span>
        ${receiptHTML}
        <span class="message-encryption-badge">🔐 E2E encrypted</span>
      </div>
    `;

    // Enlarge handler
    const enlargeBtn = msgEl.querySelector('.media-enlarge-btn');
    enlargeBtn?.addEventListener('click', () => openLightbox(mediaURL, 'video', fileType));

    // Download handler
    const dlBtn = msgEl.querySelector('.media-download-btn');
    dlBtn?.addEventListener('click', () => downloadBlob(fileBlob || mediaURL, fileName || 'video.mp4'));

    messagesContainer.appendChild(msgEl);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  function appendFileMessage({ sender, senderColor, fileName, fileSize, fileType, fileBlob, isSent, timestamp, verified }) {
    const msgEl = document.createElement('div');
    msgEl.classList.add('message', isSent ? 'sent' : 'received');
    const time = new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const color = senderColor || generateAvatarColor(sender);
    const sizeStr = formatFileSize(fileSize);
    const icon = getFileIcon(fileType);
    const verifiedBadge = verified === true ? '<span class="verified-badge" title="HMAC verified">✅</span>' :
      verified === false ? '<span class="verified-badge tampered" title="HMAC verification failed">⚠️</span>' : '';
    const receiptHTML = isSent ? '<span class="message-receipt"><span class="receipt-check">✓</span></span>' : '';

    msgEl.innerHTML = `
      <div class="message-header">
        ${avatarHTML(sender, color, 'sm')}
        <span class="message-sender">${escapeHtml(sender)}</span>
        ${verifiedBadge}
      </div>
      <div class="message-file">
        <div class="file-icon">${icon}</div>
        <div class="file-info">
          <div class="file-name">${escapeHtml(fileName)}</div>
          <div class="file-size">${sizeStr}</div>
        </div>
        <button class="file-download-btn" title="Download">⬇️</button>
      </div>
      <div class="message-footer">
        <span class="message-time">${time}</span>
        ${receiptHTML}
        <span class="message-encryption-badge">🔐 E2E encrypted</span>
      </div>
    `;

    // Download handler — always present for both sender and receiver
    const dlBtn = msgEl.querySelector('.file-download-btn');
    dlBtn?.addEventListener('click', () => downloadBlob(fileBlob, fileName));

    messagesContainer.appendChild(msgEl);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  function appendVoiceMessage({ sender, senderColor, audioBlob, duration, isSent, timestamp }) {
    const msgEl = document.createElement('div');
    msgEl.classList.add('message', isSent ? 'sent' : 'received');
    const time = new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const color = senderColor || generateAvatarColor(sender);
    const audioUrl = URL.createObjectURL(audioBlob);

    msgEl.innerHTML = `
      <div class="message-header">
        ${avatarHTML(sender, color, 'sm')}
        <span class="message-sender">${escapeHtml(sender)}</span>
      </div>
      <div class="message-voice">
        <button class="voice-play-btn" title="Play">▶</button>
        <div class="voice-waveform">
          ${generateWaveformBars()}
        </div>
        <span class="voice-duration">${formatDuration(duration)}</span>
        <audio src="${audioUrl}" preload="metadata"></audio>
      </div>
      <div class="message-footer">
        <span class="message-time">${time}</span>
        <span class="message-encryption-badge">🔐 Voice encrypted</span>
      </div>
    `;

    // Audio play/pause
    const playBtn = msgEl.querySelector('.voice-play-btn');
    const audio = msgEl.querySelector('audio');
    const durationEl = msgEl.querySelector('.voice-duration');
    const bars = msgEl.querySelectorAll('.waveform-bar');

    audio.addEventListener('loadedmetadata', () => {
      if (audio.duration && isFinite(audio.duration)) {
        durationEl.textContent = formatDuration(Math.floor(audio.duration));
      }
    });

    playBtn?.addEventListener('click', () => {
      if (audio.paused) {
        audio.play();
        playBtn.textContent = '⏸';
        animateWaveform(bars, true);
      } else {
        audio.pause();
        playBtn.textContent = '▶';
        animateWaveform(bars, false);
      }
    });

    audio.addEventListener('ended', () => {
      playBtn.textContent = '▶';
      animateWaveform(bars, false);
    });

    messagesContainer.appendChild(msgEl);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  function appendSystemMessage(text) {
    const el = document.createElement('div');
    el.classList.add('system-message');
    el.textContent = text;
    messagesContainer.appendChild(el);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  // ══════════════════════════════════════════════════════════════
  //  LIGHTBOX & DOWNLOAD HELPERS
  // ══════════════════════════════════════════════════════════════

  function downloadBlob(blobOrUrl, fileName) {
    let url;
    if (blobOrUrl instanceof Blob || blobOrUrl instanceof File) {
      url = URL.createObjectURL(blobOrUrl);
    } else if (typeof blobOrUrl === 'string') {
      url = blobOrUrl;
    } else { return; }
    const a = document.createElement('a');
    a.href = url; a.download = fileName || 'download';
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    if (blobOrUrl instanceof Blob || blobOrUrl instanceof File) URL.revokeObjectURL(url);
  }

  function openLightbox(src, type, mimeType) {
    // Remove existing lightbox if any
    document.getElementById('media-lightbox')?.remove();

    const overlay = document.createElement('div');
    overlay.id = 'media-lightbox';
    overlay.className = 'lightbox-overlay';

    if (type === 'video') {
      overlay.innerHTML = `
        <div class="lightbox-content">
          <video src="${src}" controls autoplay playsinline class="lightbox-media"></video>
          <button class="lightbox-close" title="Close">✕</button>
        </div>
      `;
    } else {
      overlay.innerHTML = `
        <div class="lightbox-content">
          <img src="${src}" class="lightbox-media" alt="Enlarged" />
          <button class="lightbox-close" title="Close">✕</button>
        </div>
      `;
    }

    overlay.addEventListener('click', (e) => {
      if (e.target === overlay || e.target.classList.contains('lightbox-close')) {
        overlay.remove();
      }
    });
    document.addEventListener('keydown', function handler(e) {
      if (e.key === 'Escape') { overlay.remove(); document.removeEventListener('keydown', handler); }
    });

    document.body.appendChild(overlay);
    requestAnimationFrame(() => overlay.classList.add('active'));
  }

  // ══════════════════════════════════════════════════════════════
  //  UTILITY FUNCTIONS
  // ══════════════════════════════════════════════════════════════

  function formatFileSize(bytes) {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0;
    let size = bytes;
    while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
    return `${size.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
  }

  function formatDuration(seconds) {
    const m = Math.floor(seconds / 60).toString().padStart(2, '0');
    const s = (seconds % 60).toString().padStart(2, '0');
    return `${m}:${s}`;
  }

  function getFileIcon(type) {
    if (!type) return '📄';
    if (type.startsWith('image/')) return '🖼️';
    if (type.startsWith('video/')) return '🎬';
    if (type.startsWith('audio/')) return '🎵';
    if (type.includes('pdf')) return '📕';
    if (type.includes('zip') || type.includes('rar') || type.includes('tar')) return '📦';
    if (type.includes('word') || type.includes('document')) return '📝';
    if (type.includes('sheet') || type.includes('excel')) return '📊';
    if (type.includes('presentation') || type.includes('powerpoint')) return '📽️';
    return '📄';
  }

  function generateWaveformBars() {
    let bars = '';
    for (let i = 0; i < 24; i++) {
      const h = 8 + Math.random() * 20;
      bars += `<div class="waveform-bar" style="height:${h}px"></div>`;
    }
    return bars;
  }

  function animateWaveform(bars, playing) {
    bars.forEach(bar => {
      if (playing) {
        bar.style.animationPlayState = 'running';
        bar.classList.add('animating');
      } else {
        bar.style.animationPlayState = 'paused';
        bar.classList.remove('animating');
      }
    });
  }

  function showError(message) {
    const el = document.createElement('div');
    el.style.cssText = `
      position: fixed; top: 20px; left: 50%; transform: translateX(-50%);
      padding: 12px 24px; background: rgba(255, 107, 107, 0.9);
      color: white; border-radius: 12px; font-size: 14px; font-weight: 500;
      z-index: 9999; animation: fadeInUp 0.3s ease-out;
    `;
    el.textContent = message;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 3000);
  }

  function shakeElement(el) {
    el.style.animation = 'none';
    void el.offsetWidth;
    el.style.animation = 'shake 0.4s ease-out';
    el.style.border = '1px solid var(--danger)';
    setTimeout(() => { el.style.border = ''; el.style.animation = ''; }, 1000);
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // ══════════════════════════════════════════════════════════════
  //  EVENT LISTENERS
  // ══════════════════════════════════════════════════════════════

  createBtn.addEventListener('click', createSession);
  joinBtn.addEventListener('click', joinSession);
  leaveBtn.addEventListener('click', leaveSession);
  sendBtn.addEventListener('click', sendMessage);

  messageInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });

  messageInput.addEventListener('input', () => { emitTyping(); });

  nicknameInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') createSession(); });
  sessionIdInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') joinSession(); });

  // Image upload (from attach button click)
  const attachBtn = document.getElementById('attach-btn');
  const fileUpload = document.getElementById('file-upload');

  attachBtn?.addEventListener('click', () => { fileUpload?.click(); });

  fileUpload?.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    if (isImageFile(file)) {
      sendImage(file);
    } else {
      showError('Only image files are allowed (JPEG, PNG, GIF, etc.)');
    }
    e.target.value = '';
  });

  // Voice button (toggle)
  const voiceBtn = document.getElementById('voice-btn');
  voiceBtn?.addEventListener('click', (e) => {
    e.preventDefault();
    if (isRecording) { stopRecording(); } else { startRecording(); }
  });

  // Copy session ID (with fallback for non-HTTPS)
  document.getElementById('copy-session-btn')?.addEventListener('click', () => {
    const text = currentSession;
    const btn = document.getElementById('copy-session-btn');
    const showCopied = () => {
      const orig = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(() => btn.textContent = orig, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(showCopied).catch(() => {
        fallbackCopy(text); showCopied();
      });
    } else {
      fallbackCopy(text); showCopied();
    }
  });

  function fallbackCopy(text) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;left:-9999px';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  }

  // Sidebar toggle
  document.getElementById('sidebar-toggle')?.addEventListener('click', () => {
    const sidebar = document.getElementById('encryption-sidebar');
    const icon = document.getElementById('sidebar-toggle-icon');
    sidebar.classList.toggle('collapsed');
    icon.classList.toggle('flipped');
  });

  // Pipeline animation toggle
  document.getElementById('animation-toggle')?.addEventListener('click', () => {
    const btn = document.getElementById('animation-toggle');
    animationMode = animationMode === 'instant' ? 'animated' : 'instant';
    btn.textContent = animationMode === 'animated' ? '⏸ Instant' : '▶ Animate';
    btn.title = animationMode === 'animated' ? 'Switch to instant rendering' : 'Animate XOR pipeline';
  });

  // ══════════════════════════════════════════════════════════════
  //  DRAG & DROP
  // ══════════════════════════════════════════════════════════════

  const chatMain = document.querySelector('.chat-main');
  const dropOverlay = document.getElementById('drop-overlay');
  let dragCounter = 0;

  chatMain?.addEventListener('dragenter', (e) => {
    e.preventDefault();
    dragCounter++;
    if (dropOverlay) dropOverlay.classList.add('active');
  });

  chatMain?.addEventListener('dragleave', (e) => {
    e.preventDefault();
    dragCounter--;
    if (dragCounter <= 0) {
      dragCounter = 0;
      if (dropOverlay) dropOverlay.classList.remove('active');
    }
  });

  chatMain?.addEventListener('dragover', (e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
  });

  chatMain?.addEventListener('drop', (e) => {
    e.preventDefault();
    dragCounter = 0;
    if (dropOverlay) dropOverlay.classList.remove('active');

    const files = Array.from(e.dataTransfer.files);
    if (!files.length || !currentSession) return;

    files.forEach(file => {
      if (isImageFile(file)) {
        sendImage(file);
      } else {
        showError(`File "${file.name}" is not an image and cannot be shared.`);
      }
    });
  });

  // ══════════════════════════════════════════════════════════════
  //  START
  // ══════════════════════════════════════════════════════════════
  initSocket();
})();
