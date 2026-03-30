const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  maxHttpBufferSize: 50e6, // 50MB for image/file pixel data
  cors: { origin: '*' }
});

app.use(express.static(path.join(__dirname, 'public')));

// ─── Session Store ───────────────────────────────────────────────────────────
const sessions = new Map(); // sessionId → { users, createdAt, messageCount }

// ─── Session History Log ─────────────────────────────────────────────────────
const sessionHistory = []; // Persistent log of all session activity
const MAX_HISTORY = 500;

function logHistory(entry) {
  sessionHistory.push({ ...entry, timestamp: Date.now() });
  if (sessionHistory.length > MAX_HISTORY) sessionHistory.shift();
}

// ─── REST Endpoints ──────────────────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/dev', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dev.html')));

app.get('/api/sessions', (req, res) => {
  const list = [];
  sessions.forEach((data, id) => {
    list.push({
      id,
      userCount: data.users.size,
      messageCount: data.messageCount || 0,
      peakUsers: data.peakUsers || 0,
      createdAt: data.createdAt
    });
  });
  res.json(list);
});

app.get('/api/history', (req, res) => {
  res.json(sessionHistory.slice(-100));
});

// ─── Socket.IO ───────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log(`⚡ Connected: ${socket.id}`);

  // ── Create Session ──
  socket.on('create-session', (nickname, callback) => {
    const sessionId = uuidv4().slice(0, 8).toUpperCase();
    sessions.set(sessionId, {
      users: new Map([[socket.id, { nickname, color: generateColor(nickname) }]]),
      createdAt: new Date().toISOString(),
      messageCount: 0,
      peakUsers: 1
    });
    socket.join(sessionId);
    socket.data.sessionId = sessionId;
    socket.data.nickname = nickname;
    socket.data.color = generateColor(nickname);

    callback({ success: true, sessionId });
    io.to(sessionId).emit('session-update', getSessionInfo(sessionId));
    io.emit('sessions-changed');

    logHistory({ type: 'session-created', sessionId, user: nickname });
    console.log(`📦 Session ${sessionId} created by ${nickname}`);
  });

  // ── Join Session ──
  socket.on('join-session', ({ sessionId, nickname }, callback) => {
    const session = sessions.get(sessionId);
    if (!session) {
      callback({ success: false, error: 'Session not found' });
      return;
    }

    const color = generateColor(nickname);
    session.users.set(socket.id, { nickname, color });
    session.peakUsers = Math.max(session.peakUsers || 0, session.users.size);

    socket.join(sessionId);
    socket.data.sessionId = sessionId;
    socket.data.nickname = nickname;
    socket.data.color = color;

    callback({ success: true, sessionId });
    io.to(sessionId).emit('session-update', getSessionInfo(sessionId));
    io.to(sessionId).emit('system-message', {
      text: `${nickname} joined the session`,
      timestamp: Date.now()
    });
    // Notify existing members to rebroadcast DH keys for the new peer
    socket.to(sessionId).emit('peer-joined', {
      peerId: socket.id,
      peerName: nickname
    });
    io.emit('sessions-changed');

    logHistory({ type: 'user-joined', sessionId, user: nickname });
    console.log(`➕ ${nickname} joined ${sessionId}`);
  });

  // ── Leave Session ──
  socket.on('leave-session', () => {
    handleLeave(socket);
  });

  // ── DH Public Key Exchange ──
  socket.on('dh-public-key', (payload) => {
    const { sessionId } = socket.data;
    if (!sessionId) return;

    // Relay public key to all other users in session
    socket.to(sessionId).emit('dh-public-key', {
      senderId: socket.id,
      senderName: socket.data.nickname,
      publicKey: payload.publicKey
    });
  });

  // ── Encrypted Message ──
  socket.on('encrypted-message', (payload) => {
    const { sessionId, nickname } = socket.data;
    if (!sessionId) return;

    const session = sessions.get(sessionId);
    if (session) session.messageCount = (session.messageCount || 0) + 1;

    const messageId = uuidv4().slice(0, 12);

    // Relay to other users in the room
    socket.to(sessionId).emit('encrypted-message', {
      messageId,
      senderId: socket.id,
      senderName: nickname,
      senderColor: socket.data.color,
      // Encrypted content
      cipherData: payload.cipherData,
      keyData: payload.keyData,
      aesCiphertext: payload.aesCiphertext,
      iv: payload.iv,
      hmac: payload.hmac,
      width: payload.width,
      height: payload.height,
      isImage: payload.isImage || false,
      isFile: payload.isFile || false,
      isVoice: payload.isVoice || false,
      isVideo: payload.isVideo || false,
      isSecure: payload.isSecure || false,
      fileMeta: payload.fileMeta || null,
      timestamp: Date.now()
    });

    // Emit back messageId to sender
    socket.emit('message-sent', { messageId, timestamp: Date.now() });

    // Send full pipeline to dev dashboard
    io.emit('dev-pipeline', {
      sessionId,
      senderName: nickname,
      messageData: payload.messageData,
      keyData: payload.keyData,
      cipherData: payload.cipherData,
      decryptedData: payload.decryptedData,
      width: payload.width,
      height: payload.height,
      originalText: payload.originalText,
      isImage: payload.isImage || false,
      isFile: payload.isFile || false,
      isVoice: payload.isVoice || false,
      timestamp: Date.now()
    });

    logHistory({
      type: 'message',
      sessionId,
      user: nickname,
      isImage: payload.isImage,
      isFile: payload.isFile,
      isVoice: payload.isVoice
    });
  });

  // ── Typing Indicator ──
  socket.on('typing', () => {
    const { sessionId, nickname } = socket.data;
    if (!sessionId) return;
    socket.to(sessionId).emit('typing', {
      senderId: socket.id,
      senderName: nickname
    });
  });

  socket.on('stop-typing', () => {
    const { sessionId, nickname } = socket.data;
    if (!sessionId) return;
    socket.to(sessionId).emit('stop-typing', {
      senderId: socket.id,
      senderName: nickname
    });
  });

  // ── Read Receipts ──
  socket.on('message-read', ({ messageId, senderId }) => {
    const { sessionId, nickname } = socket.data;
    if (!sessionId) return;
    // Notify the original sender their message was read
    io.to(senderId).emit('message-read', {
      messageId,
      readBy: nickname,
      timestamp: Date.now()
    });
  });

  // ── Disconnect ──
  socket.on('disconnect', () => {
    handleLeave(socket);
    console.log(`💤 Disconnected: ${socket.id}`);
  });
});

function handleLeave(socket) {
  const { sessionId, nickname } = socket.data;
  if (!sessionId) return;

  const session = sessions.get(sessionId);
  if (session) {
    session.users.delete(socket.id);
    socket.leave(sessionId);

    if (session.users.size === 0) {
      logHistory({
        type: 'session-ended', sessionId,
        messageCount: session.messageCount,
        peakUsers: session.peakUsers,
        duration: Date.now() - new Date(session.createdAt).getTime()
      });
      sessions.delete(sessionId);
      console.log(`🗑️  Session ${sessionId} deleted (empty)`);
    } else {
      io.to(sessionId).emit('session-update', getSessionInfo(sessionId));
      io.to(sessionId).emit('system-message', {
        text: `${nickname} left the session`,
        timestamp: Date.now()
      });
    }
    io.emit('sessions-changed');
  }

  logHistory({ type: 'user-left', sessionId, user: nickname });
  socket.data.sessionId = null;
  socket.data.nickname = null;
}

function getSessionInfo(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return null;

  const users = [];
  session.users.forEach((data) => {
    users.push({ nickname: data.nickname, color: data.color });
  });

  return {
    sessionId,
    users: users.map(u => u.nickname),
    userDetails: users,
    userCount: session.users.size,
    messageCount: session.messageCount || 0,
    createdAt: session.createdAt
  };
}

/**
 * Generate a deterministic HSL color from a nickname.
 */
function generateColor(nickname) {
  let hash = 0;
  for (let i = 0; i < nickname.length; i++) {
    hash = nickname.charCodeAt(i) + ((hash << 5) - hash);
    hash = hash & hash;
  }
  const hue = Math.abs(hash % 360);
  return `hsl(${hue}, 70%, 60%)`;
}

// ─── Start ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';

function getLocalIP() {
  const os = require('os');
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return 'localhost';
}

server.listen(PORT, HOST, () => {
  const localIP = getLocalIP();
  console.log(`\n🔐 CipherChat — Image Encryption Chat`);
  console.log(`   Local:   http://localhost:${PORT}`);
  console.log(`   Network: http://${localIP}:${PORT}`);
  console.log(`\n🛠️  Developer Dashboard`);
  console.log(`   Local:   http://localhost:${PORT}/dev`);
  console.log(`   Network: http://${localIP}:${PORT}/dev`);
  console.log(`\n📊 Session History API`);
  console.log(`   http://localhost:${PORT}/api/history\n`);
});
