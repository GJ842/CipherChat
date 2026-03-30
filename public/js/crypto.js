/**
 * ╔═══════════════════════════════════════════════════════════════╗
 * ║        IMAGE-BASED ENCRYPTION ENGINE v2.0                     ║
 * ║  ECDH Key Exchange · AES-256-GCM · HMAC Signing               ║
 * ║  XOR Pixel Encryption · Voice & File Encryption               ║
 * ╚═══════════════════════════════════════════════════════════════╝
 */

const ImageCrypto = (() => {
  // ══════════════════════════════════════════════════════════════
  //  CONSTANTS
  // ══════════════════════════════════════════════════════════════
  const CANVAS_WIDTH = 64;
  const CANVAS_HEIGHT = 64;
  const MAX_BYTES = CANVAS_WIDTH * CANVAS_HEIGHT * 3;
  const MAX_IMG_DIMENSION = 256;

  // ══════════════════════════════════════════════════════════════
  //  ECDH KEY EXCHANGE (Diffie-Hellman)
  // ══════════════════════════════════════════════════════════════

  /**
   * Generate an ECDH key pair for Diffie-Hellman key exchange.
   * Returns: { publicKey (exportable JWK), privateKey (CryptoKey) }
   */
  async function generateKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true, // extractable
      ['deriveKey', 'deriveBits']
    );

    // Export public key as JWK for transmission
    const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

    return {
      publicKey: publicKeyJwk,
      privateKey: keyPair.privateKey,
      publicCryptoKey: keyPair.publicKey
    };
  }

  /**
   * Derive shared AES + HMAC keys from own private key + peer's public key.
   * Uses ECDH to derive bits, then HKDF to split into AES key + HMAC key.
   */
  async function deriveSharedKeys(myPrivateKey, peerPublicKeyJwk) {
    // Import peer's public key
    const peerPublicKey = await crypto.subtle.importKey(
      'jwk', peerPublicKeyJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      false, []
    );

    // Derive shared bits via ECDH
    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: peerPublicKey },
      myPrivateKey, 256
    );

    // Import as HKDF key material
    const hkdfKey = await crypto.subtle.importKey(
      'raw', sharedBits, 'HKDF', false, ['deriveKey']
    );

    // Derive AES-256-GCM key
    const aesKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new TextEncoder().encode('CipherChat-AES-v2'),
        info: new TextEncoder().encode('aes-encryption')
      },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    // Derive HMAC key (separate from AES)
    const hmacKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new TextEncoder().encode('CipherChat-HMAC-v2'),
        info: new TextEncoder().encode('hmac-signing')
      },
      hkdfKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      false,
      ['sign', 'verify']
    );

    return { aesKey, hmacKey };
  }

  // ══════════════════════════════════════════════════════════════
  //  AES-256-GCM ENCRYPTION
  // ══════════════════════════════════════════════════════════════

  /**
   * Encrypt data with AES-256-GCM.
   * Returns: { ciphertext (ArrayBuffer), iv (Uint8Array) }
   */
  async function aesEncrypt(aesKey, data) {
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
    const dataBuffer = data instanceof ArrayBuffer ? data : new Uint8Array(data).buffer;

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey, dataBuffer
    );

    return {
      ciphertext: Array.from(new Uint8Array(ciphertext)),
      iv: Array.from(iv)
    };
  }

  /**
   * Decrypt AES-256-GCM ciphertext.
   */
  async function aesDecrypt(aesKey, ciphertextArray, ivArray) {
    const ciphertext = new Uint8Array(ciphertextArray).buffer;
    const iv = new Uint8Array(ivArray);

    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      aesKey, ciphertext
    );

    return new Uint8Array(plaintext);
  }

  // ══════════════════════════════════════════════════════════════
  //  HMAC MESSAGE SIGNING
  // ══════════════════════════════════════════════════════════════

  /**
   * Sign data with HMAC-SHA256.
   */
  async function hmacSign(hmacKey, data) {
    const dataBuffer = new Uint8Array(data).buffer;
    const signature = await crypto.subtle.sign('HMAC', hmacKey, dataBuffer);
    return Array.from(new Uint8Array(signature));
  }

  /**
   * Verify HMAC-SHA256 signature.
   */
  async function hmacVerify(hmacKey, data, signatureArray) {
    const dataBuffer = new Uint8Array(data).buffer;
    const signature = new Uint8Array(signatureArray).buffer;
    return await crypto.subtle.verify('HMAC', hmacKey, signature, dataBuffer);
  }

  // ══════════════════════════════════════════════════════════════
  //  XOR PIXEL ENCRYPTION (original engine)
  // ══════════════════════════════════════════════════════════════

  function textToImageData(text) {
    const canvas = document.createElement('canvas');
    canvas.width = CANVAS_WIDTH;
    canvas.height = CANVAS_HEIGHT;
    const ctx = canvas.getContext('2d');
    const imageData = ctx.createImageData(CANVAS_WIDTH, CANVAS_HEIGHT);
    const data = imageData.data;

    const encoder = new TextEncoder();
    const textBytes = encoder.encode(text);
    const length = textBytes.length;

    if (length > MAX_BYTES - 4) {
      throw new Error(`Message too long. Max ${MAX_BYTES - 4} bytes.`);
    }

    const lengthBytes = new Uint8Array(4);
    lengthBytes[0] = (length >> 24) & 0xff;
    lengthBytes[1] = (length >> 16) & 0xff;
    lengthBytes[2] = (length >> 8) & 0xff;
    lengthBytes[3] = length & 0xff;

    const allBytes = new Uint8Array(4 + length);
    allBytes.set(lengthBytes, 0);
    allBytes.set(textBytes, 4);

    let byteIndex = 0;
    for (let i = 0; i < data.length; i += 4) {
      data[i] = byteIndex < allBytes.length ? allBytes[byteIndex++] : 0;
      data[i + 1] = byteIndex < allBytes.length ? allBytes[byteIndex++] : 0;
      data[i + 2] = byteIndex < allBytes.length ? allBytes[byteIndex++] : 0;
      data[i + 3] = 255;
    }

    ctx.putImageData(imageData, 0, 0);
    return { imageData, dataArray: Array.from(data), width: CANVAS_WIDTH, height: CANVAS_HEIGHT };
  }

  function generateKeyImage() {
    const canvas = document.createElement('canvas');
    canvas.width = CANVAS_WIDTH;
    canvas.height = CANVAS_HEIGHT;
    const ctx = canvas.getContext('2d');
    const imageData = ctx.createImageData(CANVAS_WIDTH, CANVAS_HEIGHT);
    const data = imageData.data;

    const randomBytes = new Uint8Array(data.length);
    crypto.getRandomValues(randomBytes);

    for (let i = 0; i < data.length; i += 4) {
      data[i] = randomBytes[i];
      data[i + 1] = randomBytes[i + 1];
      data[i + 2] = randomBytes[i + 2];
      data[i + 3] = 255;
    }

    ctx.putImageData(imageData, 0, 0);
    return { imageData, dataArray: Array.from(data), width: CANVAS_WIDTH, height: CANVAS_HEIGHT };
  }

  function generateKeyImageSized(width, height) {
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');
    const imageData = ctx.createImageData(width, height);
    const data = imageData.data;

    const chunkSize = 65536;
    for (let offset = 0; offset < data.length; offset += chunkSize) {
      const len = Math.min(chunkSize, data.length - offset);
      const randomChunk = new Uint8Array(len);
      crypto.getRandomValues(randomChunk);
      for (let i = 0; i < len; i++) {
        if ((offset + i) % 4 === 3) {
          data[offset + i] = 255;
        } else {
          data[offset + i] = randomChunk[i];
        }
      }
    }

    ctx.putImageData(imageData, 0, 0);
    return { imageData, dataArray: Array.from(data), width, height };
  }

  function xorImages(dataArrayA, dataArrayB, w, h) {
    const len = Math.min(dataArrayA.length, dataArrayB.length);
    const width = w || CANVAS_WIDTH;
    const height = h || CANVAS_HEIGHT;

    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');
    const imageData = ctx.createImageData(width, height);
    const result = imageData.data;

    for (let i = 0; i < len; i += 4) {
      result[i] = dataArrayA[i] ^ dataArrayB[i];
      result[i + 1] = dataArrayA[i + 1] ^ dataArrayB[i + 1];
      result[i + 2] = dataArrayA[i + 2] ^ dataArrayB[i + 2];
      result[i + 3] = 255;
    }

    ctx.putImageData(imageData, 0, 0);
    return { imageData, dataArray: Array.from(result), width, height };
  }

  function imageDataToText(dataArray) {
    const bytes = [];
    for (let i = 0; i < dataArray.length; i += 4) {
      bytes.push(dataArray[i], dataArray[i + 1], dataArray[i + 2]);
    }

    const length = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    if (length <= 0 || length > MAX_BYTES - 4) return '[decryption error]';

    const textBytes = new Uint8Array(bytes.slice(4, 4 + length));
    return new TextDecoder().decode(textBytes);
  }

  // ══════════════════════════════════════════════════════════════
  //  MULTI-LAYER ENCRYPTION (XOR + AES + HMAC)
  // ══════════════════════════════════════════════════════════════

  /**
   * Generic E2E encryption for any pixel data:
   * pixels → XOR(pixels, randomKey) → AES-encrypt(XOR+key bundle) → HMAC sign
   */
  async function encryptSecurePixels(pixelDataArray, width, height, aesKey, hmacKey) {
    const keyImg = generateKeyImageSized(width, height);
    const cipherImg = xorImages(pixelDataArray, keyImg.dataArray, width, height);

    const bundle = new Uint8Array(cipherImg.dataArray.length + keyImg.dataArray.length);
    bundle.set(new Uint8Array(cipherImg.dataArray), 0);
    bundle.set(new Uint8Array(keyImg.dataArray), cipherImg.dataArray.length);

    const aesResult = await aesEncrypt(aesKey, bundle);
    const hmac = await hmacSign(hmacKey, aesResult.ciphertext);

    return {
      aesCiphertext: aesResult.ciphertext,
      iv: aesResult.iv,
      hmac,
      width,
      height,
      _pipeline: {
        messageData: Array.from(pixelDataArray),
        keyData: keyImg.dataArray,
        cipherData: cipherImg.dataArray,
        decryptedData: xorImages(cipherImg.dataArray, keyImg.dataArray, width, height).dataArray
      }
    };
  }

  /**
   * Generic E2E decryption for any pixel data:
   * verify HMAC → AES-decrypt → extract XOR cipher + key → XOR decrypt → pixels
   */
  async function decryptSecurePixels(aesCiphertext, iv, hmacSig, aesKey, hmacKey, width, height) {
    const verified = await hmacVerify(hmacKey, aesCiphertext, hmacSig);
    const bundle = await aesDecrypt(aesKey, aesCiphertext, iv);

    const pixelCount = width * height * 4;
    const cipherData = Array.from(bundle.slice(0, pixelCount));
    const keyData = Array.from(bundle.slice(pixelCount, pixelCount * 2));

    const decryptedImg = xorImages(cipherData, keyData, width, height);

    return {
      decryptedData: decryptedImg.dataArray,
      verified,
      cipherData,
      keyData,
      width,
      height
    };
  }

  /** Convenience: E2E encrypt text (text → pixels → encryptSecurePixels) */
  async function encryptSecure(text, aesKey, hmacKey) {
    const messageImg = textToImageData(text);
    return encryptSecurePixels(messageImg.dataArray, messageImg.width, messageImg.height, aesKey, hmacKey);
  }

  /** Convenience: E2E decrypt text (decryptSecurePixels → pixels → text) */
  async function decryptSecure(aesCiphertext, iv, hmacSig, aesKey, hmacKey, width, height) {
    const result = await decryptSecurePixels(aesCiphertext, iv, hmacSig, aesKey, hmacKey, width, height);
    const text = imageDataToText(result.decryptedData);
    return { ...result, text };
  }

  // ── Fallback (non-secure context) ──
  function encrypt(text) {
    const messageImg = textToImageData(text);
    const keyImg = generateKeyImage();
    const cipherImg = xorImages(messageImg.dataArray, keyImg.dataArray);
    const decryptedImg = xorImages(cipherImg.dataArray, keyImg.dataArray);
    return {
      messageData: messageImg.dataArray,
      keyData: keyImg.dataArray,
      cipherData: cipherImg.dataArray,
      decryptedData: decryptedImg.dataArray,
      width: CANVAS_WIDTH, height: CANVAS_HEIGHT,
      originalText: text
    };
  }

  function decrypt(cipherDataArray, keyDataArray) {
    const decryptedImg = xorImages(cipherDataArray, keyDataArray);
    const text = imageDataToText(decryptedImg.dataArray);
    return { decryptedData: decryptedImg.dataArray, text, width: CANVAS_WIDTH, height: CANVAS_HEIGHT };
  }

  // ══════════════════════════════════════════════════════════════
  //  IMAGE FILE ENCRYPTION
  // ══════════════════════════════════════════════════════════════

  function loadImageFromFile(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const img = new Image();
        img.onload = () => {
          let w = img.width, h = img.height;
          if (w > MAX_IMG_DIMENSION || h > MAX_IMG_DIMENSION) {
            const ratio = Math.min(MAX_IMG_DIMENSION / w, MAX_IMG_DIMENSION / h);
            w = Math.round(w * ratio);
            h = Math.round(h * ratio);
          }
          const canvas = document.createElement('canvas');
          canvas.width = w; canvas.height = h;
          const ctx = canvas.getContext('2d');
          ctx.drawImage(img, 0, 0, w, h);
          const imageData = ctx.getImageData(0, 0, w, h);
          resolve({ dataArray: Array.from(imageData.data), width: w, height: h });
        };
        img.onerror = reject;
        img.src = e.target.result;
      };
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }

  function encryptImage(imgDataArray, width, height) {
    const keyImg = generateKeyImageSized(width, height);
    const cipherImg = xorImages(imgDataArray, keyImg.dataArray, width, height);
    const decryptedImg = xorImages(cipherImg.dataArray, keyImg.dataArray, width, height);
    return {
      messageData: imgDataArray, keyData: keyImg.dataArray,
      cipherData: cipherImg.dataArray, decryptedData: decryptedImg.dataArray,
      width, height
    };
  }

  function decryptImage(cipherDataArray, keyDataArray, width, height) {
    const decryptedImg = xorImages(cipherDataArray, keyDataArray, width, height);
    return { decryptedData: decryptedImg.dataArray, width, height };
  }

  // ══════════════════════════════════════════════════════════════
  //  FILE ENCRYPTION (any file type)
  // ══════════════════════════════════════════════════════════════

  /**
   * Read a file as ArrayBuffer, encode into pixel data for XOR encryption.
   * Metadata (name, type, size) stored in first bytes.
   */
  function loadFileAsPixels(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const fileBytes = new Uint8Array(e.target.result);
        const metaStr = JSON.stringify({
          name: file.name,
          type: file.type || 'application/octet-stream',
          size: file.size
        });
        const metaBytes = new TextEncoder().encode(metaStr);

        // Format: [4B meta length][meta bytes][4B file length][file bytes]
        const totalLen = 4 + metaBytes.length + 4 + fileBytes.length;
        const allBytes = new Uint8Array(totalLen);
        let offset = 0;

        // Meta length (4 bytes)
        allBytes[offset++] = (metaBytes.length >> 24) & 0xff;
        allBytes[offset++] = (metaBytes.length >> 16) & 0xff;
        allBytes[offset++] = (metaBytes.length >> 8) & 0xff;
        allBytes[offset++] = metaBytes.length & 0xff;
        allBytes.set(metaBytes, offset); offset += metaBytes.length;

        // File length (4 bytes)
        allBytes[offset++] = (fileBytes.length >> 24) & 0xff;
        allBytes[offset++] = (fileBytes.length >> 16) & 0xff;
        allBytes[offset++] = (fileBytes.length >> 8) & 0xff;
        allBytes[offset++] = fileBytes.length & 0xff;
        allBytes.set(fileBytes, offset);

        // Calculate canvas dimensions to fit all bytes
        const pixelCount = Math.ceil(totalLen / 3);
        const side = Math.ceil(Math.sqrt(pixelCount));
        const w = side, h = side;

        const pixelData = new Array(w * h * 4).fill(0);
        let byteIdx = 0;
        for (let i = 0; i < pixelData.length; i += 4) {
          pixelData[i] = byteIdx < allBytes.length ? allBytes[byteIdx++] : 0;
          pixelData[i + 1] = byteIdx < allBytes.length ? allBytes[byteIdx++] : 0;
          pixelData[i + 2] = byteIdx < allBytes.length ? allBytes[byteIdx++] : 0;
          pixelData[i + 3] = 255;
        }

        resolve({ dataArray: pixelData, width: w, height: h, fileName: file.name, fileType: file.type, fileSize: file.size });
      };
      reader.onerror = reject;
      reader.readAsArrayBuffer(file);
    });
  }

  /**
   * Extract file from decrypted pixel data.
   */
  function pixelsToFile(dataArray) {
    const bytes = [];
    for (let i = 0; i < dataArray.length; i += 4) {
      bytes.push(dataArray[i], dataArray[i + 1], dataArray[i + 2]);
    }

    let offset = 0;
    const metaLen = (bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
    offset += 4;
    const metaBytes = new Uint8Array(bytes.slice(offset, offset + metaLen));
    const meta = JSON.parse(new TextDecoder().decode(metaBytes));
    offset += metaLen;

    const fileLen = (bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
    offset += 4;
    const fileBytes = new Uint8Array(bytes.slice(offset, offset + fileLen));

    const blob = new Blob([fileBytes], { type: meta.type });
    return { blob, name: meta.name, type: meta.type, size: meta.size };
  }

  function encryptFile(filePixelData, width, height) {
    return encryptImage(filePixelData, width, height);
  }

  function decryptFile(cipherData, keyData, width, height) {
    const result = decryptImage(cipherData, keyData, width, height);
    const file = pixelsToFile(result.decryptedData);
    return { ...result, file };
  }

  // ══════════════════════════════════════════════════════════════
  //  VOICE MESSAGE ENCRYPTION
  // ══════════════════════════════════════════════════════════════

  function loadAudioAsPixels(audioBlob) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const audioBytes = new Uint8Array(e.target.result);
        const totalLen = 4 + audioBytes.length;

        const allBytes = new Uint8Array(totalLen);
        allBytes[0] = (audioBytes.length >> 24) & 0xff;
        allBytes[1] = (audioBytes.length >> 16) & 0xff;
        allBytes[2] = (audioBytes.length >> 8) & 0xff;
        allBytes[3] = audioBytes.length & 0xff;
        allBytes.set(audioBytes, 4);

        const pixelCount = Math.ceil(totalLen / 3);
        const side = Math.ceil(Math.sqrt(pixelCount));
        const w = side, h = side;

        const pixelData = new Array(w * h * 4).fill(0);
        let byteIdx = 0;
        for (let i = 0; i < pixelData.length; i += 4) {
          pixelData[i] = byteIdx < allBytes.length ? allBytes[byteIdx++] : 0;
          pixelData[i + 1] = byteIdx < allBytes.length ? allBytes[byteIdx++] : 0;
          pixelData[i + 2] = byteIdx < allBytes.length ? allBytes[byteIdx++] : 0;
          pixelData[i + 3] = 255;
        }

        resolve({ dataArray: pixelData, width: w, height: h });
      };
      reader.onerror = reject;
      reader.readAsArrayBuffer(audioBlob);
    });
  }

  function pixelsToAudio(dataArray) {
    const bytes = [];
    for (let i = 0; i < dataArray.length; i += 4) {
      bytes.push(dataArray[i], dataArray[i + 1], dataArray[i + 2]);
    }

    const audioLen = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    const audioBytes = new Uint8Array(bytes.slice(4, 4 + audioLen));
    return new Blob([audioBytes], { type: 'audio/webm;codecs=opus' });
  }

  // ══════════════════════════════════════════════════════════════
  //  PIPELINE ANIMATION
  // ══════════════════════════════════════════════════════════════

  /**
   * Animate XOR encryption pixel-by-pixel on a canvas.
   * Renders progressively over `durationMs` milliseconds.
   */
  function animateXorPipeline(sourceData, keyData, canvasElement, durationMs = 2000) {
    const w = canvasElement.width || CANVAS_WIDTH;
    const h = canvasElement.height || CANVAS_HEIGHT;
    const ctx = canvasElement.getContext('2d');
    const imageData = ctx.createImageData(w, h);
    const totalPixels = w * h;
    const pixelsPerFrame = Math.max(1, Math.floor(totalPixels / (durationMs / 16)));
    let currentPixel = 0;

    return new Promise((resolve) => {
      function frame() {
        const end = Math.min(currentPixel + pixelsPerFrame, totalPixels);
        for (let p = currentPixel; p < end; p++) {
          const i = p * 4;
          imageData.data[i] = (sourceData[i] || 0) ^ (keyData[i] || 0);
          imageData.data[i + 1] = (sourceData[i + 1] || 0) ^ (keyData[i + 1] || 0);
          imageData.data[i + 2] = (sourceData[i + 2] || 0) ^ (keyData[i + 2] || 0);
          imageData.data[i + 3] = 255;
        }
        currentPixel = end;
        ctx.putImageData(imageData, 0, 0);

        if (currentPixel < totalPixels) {
          requestAnimationFrame(frame);
        } else {
          resolve();
        }
      }
      requestAnimationFrame(frame);
    });
  }

  // ══════════════════════════════════════════════════════════════
  //  RENDERING
  // ══════════════════════════════════════════════════════════════

  function dataArrayToDataURL(dataArray, width, height) {
    const canvas = document.createElement('canvas');
    canvas.width = width; canvas.height = height;
    const ctx = canvas.getContext('2d');
    const imageData = ctx.createImageData(width, height);
    for (let i = 0; i < dataArray.length && i < imageData.data.length; i++) {
      imageData.data[i] = dataArray[i];
    }
    ctx.putImageData(imageData, 0, 0);
    return canvas.toDataURL('image/png');
  }

  function renderToCanvas(canvasElement, dataArray, width, height) {
    canvasElement.width = width || CANVAS_WIDTH;
    canvasElement.height = height || CANVAS_HEIGHT;
    const ctx = canvasElement.getContext('2d');
    const imageData = ctx.createImageData(canvasElement.width, canvasElement.height);
    for (let i = 0; i < dataArray.length && i < imageData.data.length; i++) {
      imageData.data[i] = dataArray[i];
    }
    ctx.putImageData(imageData, 0, 0);
    ctx.imageSmoothingEnabled = false;
  }

  // ══════════════════════════════════════════════════════════════
  //  UTILITY: Check if secure context is available
  // ══════════════════════════════════════════════════════════════

  function isSecureContext() {
    return window.isSecureContext && typeof crypto.subtle !== 'undefined';
  }

  // ══════════════════════════════════════════════════════════════
  //  PUBLIC API
  // ══════════════════════════════════════════════════════════════

  return {
    // Constants
    CANVAS_WIDTH, CANVAS_HEIGHT, MAX_IMG_DIMENSION,
    // Key exchange
    generateKeyPair, deriveSharedKeys, isSecureContext,
    // AES
    aesEncrypt, aesDecrypt,
    // HMAC
    hmacSign, hmacVerify,
    // XOR (core)
    textToImageData, generateKeyImage, generateKeyImageSized,
    xorImages, imageDataToText,
    // Multi-layer encryption
    encryptSecure, decryptSecure, encryptSecurePixels, decryptSecurePixels,
    // Fallback (no DH)
    encrypt, decrypt,
    // Image encryption
    loadImageFromFile, encryptImage, decryptImage,
    // File encryption
    loadFileAsPixels, pixelsToFile, encryptFile, decryptFile,
    // Voice encryption
    loadAudioAsPixels, pixelsToAudio,
    // Animation
    animateXorPipeline,
    // Rendering
    dataArrayToDataURL, renderToCanvas
  };
})();
