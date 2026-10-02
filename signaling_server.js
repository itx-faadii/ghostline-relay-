import { WebSocketServer } from 'ws';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const port = Number(process.env.PORT || 8787);
const maxMessageBytes = 64 * 1024;
const registrationTimeoutMs = 10_000;
const queueLimit = 20;
const queueTtlMs = 60_000;
const rateCapacity = 100;
const rateRefillPerSecond = 20;
const allowedMessageTypes = new Set([
  'register',
  'blind_join',
  'blind_signal',
  'signal',
]);
const peers = new Map();
const topics = new Map();
const queuedSignals = new Map();

function send(socket, message) {
  if (socket.readyState === socket.OPEN) {
    socket.send(JSON.stringify(message));
  }
}

function removePeer(socket) {
  if (socket.peerId && peers.get(socket.peerId) === socket) {
    peers.delete(socket.peerId);
  }
  if (socket.topics) {
    for (const topic of socket.topics) {
      const set = topics.get(topic);
      if (set) {
        set.delete(socket);
        if (set.size === 0) topics.delete(topic);
      }
    }
    socket.topics.clear();
  }
}

function consumeRateToken(socket) {
  const now = Date.now();
  const elapsedSeconds = (now - socket.rate.updatedAt) / 1000;
  socket.rate.tokens = Math.min(
    rateCapacity,
    socket.rate.tokens + elapsedSeconds * rateRefillPerSecond,
  );
  socket.rate.updatedAt = now;
  if (socket.rate.tokens < 1) return false;
  socket.rate.tokens -= 1;
  return true;
}

function queueSignal(peerId, message) {
  const now = Date.now();
  const existing = (queuedSignals.get(peerId) || [])
    .filter((entry) => entry.expiresAt > now);
  if (existing.length >= queueLimit) existing.shift();
  existing.push({
    message,
    expiresAt: now + queueTtlMs,
  });
  queuedSignals.set(peerId, existing);
}

function flushQueuedSignals(peerId, socket) {
  const now = Date.now();
  const queued = queuedSignals.get(peerId) || [];
  queuedSignals.delete(peerId);
  for (const entry of queued) {
    if (entry.expiresAt > now) send(socket, entry.message);
  }
}

function verifyRegistration(peerId, encodedPublicKey, encodedSignature) {
  try {
    const publicKey = Buffer.from(encodedPublicKey, 'base64url');
    const signature = Buffer.from(encodedSignature, 'base64url');
    const fingerprint = crypto
      .createHash('sha256')
      .update(publicKey)
      .digest('base64url')
      .replace(/=+$/g, '')
      .slice(0, 22);
    const claimedFingerprint = Buffer.from(peerId, 'utf8');
    const actualFingerprint = Buffer.from(fingerprint, 'utf8');
    if (claimedFingerprint.length !== actualFingerprint.length ||
        !crypto.timingSafeEqual(claimedFingerprint, actualFingerprint)) {
      return false;
    }

    if (publicKey.length === 32) {
      const ed25519Key = crypto.createPublicKey({
        key: Buffer.concat([
          Buffer.from('302a300506032b6570032100', 'hex'),
          publicKey,
        ]),
        format: 'der',
        type: 'spki',
      });
      return crypto.verify(null, claimedFingerprint, ed25519Key, signature);
    }

    let encodedKey = publicKey;
    if (publicKey.length === 65 && publicKey[0] === 0x04) {
      encodedKey = Buffer.concat([
        Buffer.from(
          '3059301306072a8648ce3d020106082a8648ce3d030107034200',
          'hex',
        ),
        publicKey,
      ]);
    } else if (publicKey.length !== 91 || publicKey[0] !== 0x30) {
      return false;
    }

    const p256Key = crypto.createPublicKey({
      key: encodedKey,
      format: 'der',
      type: 'spki',
    });
    const dsaEncoding = signature[0] === 0x30
      ? 'der'
      : signature.length === 64
          ? 'ieee-p1363'
          : null;
    if (dsaEncoding === null) return false;
    return crypto.verify(
      'sha256',
      claimedFingerprint,
      { key: p256Key, dsaEncoding },
      signature,
    );
  } catch {
    return false;
  }
}

function startServer() {
  const server = new WebSocketServer({ port });
     const heartbeat = setInterval(() => {
    for (const client of server.clients) {
      if (client.isAlive === false) {
        client.terminate();
        continue;
      }
      client.isAlive = false;
      client.ping();
    }
  }, 15000);
  server.on('close', () => clearInterval(heartbeat));
  
  server.on('connection', (socket) => {
      socket.isAlive = true;
  socket.on('pong', () => { socket.isAlive = true; });
  socket.topics = new Set();
  socket.rate = {
    tokens: rateCapacity,
    updatedAt: Date.now(),
  };
  socket.registrationTimer = setTimeout(() => {
    if (typeof socket.peerId !== 'string') {
      socket.close(1008, 'registration timeout');
    }
  }, registrationTimeoutMs);

  socket.on('message', (raw) => {
    if (!consumeRateToken(socket)) {
      socket.close(1008, 'rate limit exceeded');
      return;
    }
    if (raw.length > maxMessageBytes) {
      socket.close(1009, 'signaling message too large');
      return;
    }

    let message;
    try {
      message = JSON.parse(raw.toString());
    } catch {
      socket.close(1003, 'invalid signaling message');
      return;
    }

    if (!allowedMessageTypes.has(message.type)) {
      send(socket, { type: 'error', code: 'unsupported_message' });
      return;
    }

    if (message.type === 'register') {
      if (typeof message.peerId !== 'string' ||
          message.peerId.length < 8 ||
          typeof message.identityKey !== 'string' ||
          typeof message.signature !== 'string' ||
          !verifyRegistration(message.peerId, message.identityKey, message.signature)) {
        socket.close(1008, 'invalid peer id');
        return;
      }
      if (peers.has(message.peerId) && peers.get(message.peerId) !== socket) {
        socket.close(1008, 'peer id already connected');
        return;
      }
      removePeer(socket);
      clearTimeout(socket.registrationTimer);
      socket.peerId = message.peerId;
      socket.identityKey = message.identityKey;
      peers.set(message.peerId, socket);
      send(socket, { type: 'registered', peerId: message.peerId });
      flushQueuedSignals(message.peerId, socket);
      return;
    }

    if (message.type === 'blind_join') {
      if (typeof message.topic !== 'string' || message.topic.length < 16) {
        send(socket, { type: 'error', code: 'invalid_topic' });
        return;
      }
      if (!topics.has(message.topic)) {
        topics.set(message.topic, new Set());
      }
      topics.get(message.topic).add(socket);
      socket.topics.add(message.topic);
      send(socket, { type: 'blind_joined', topic: message.topic });
      return;
    }

    if (message.type === 'blind_signal') {
      if (typeof message.topic !== 'string' ||
          typeof message.payload !== 'object' ||
          message.payload === null) {
        send(socket, { type: 'error', code: 'invalid_blind_signal' });
        return;
      }
      const subscribers = topics.get(message.topic);
      if (subscribers) {
        for (const recipient of subscribers) {
          if (recipient !== socket) {
            send(recipient, {
              type: 'blind_signal',
              topic: message.topic,
              payload: message.payload,
            });
          }
        }
      }
      return;
    }

    if (message.type === 'signal') {
      if (typeof socket.peerId !== 'string' ||
          typeof message.to !== 'string' ||
          typeof message.payload !== 'object' ||
          message.payload === null) {
        send(socket, { type: 'error', code: 'invalid_signal' });
        return;
      }
      const recipient = peers.get(message.to);
      if (recipient) {
        send(recipient, {
          type: 'signal',
          from: socket.peerId,
          payload: message.payload,
        });
      } else {
        queueSignal(message.to, {
          type: 'signal',
          from: socket.peerId,
          payload: message.payload,
        });
      }
      return;
    }

  });

   socket.on('close', (code, reason) => {
    console.log(`socket closed code=${code} reason=${reason.toString()}`);
    clearTimeout(socket.registrationTimer);
    removePeer(socket);
  });
  socket.on('error', () => {
    clearTimeout(socket.registrationTimer);
    removePeer(socket);
  });
  });

  console.log(`GhostLine signaling relay listening on :${port}`);
}

export { verifyRegistration, startServer };

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  startServer();
}
