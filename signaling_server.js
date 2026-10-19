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

// Offline store-and-forward. The broker holds opaque, already-encrypted message
// blobs for peers that are not connected, and pushes them on registration. It
// never sees plaintext, but it does now retain: recipient id, sender id, message
// id, blob size and arrival time - which PRIVACY_POLICY.md and DEPLOY.md state.
const storedLimitPerPeer = 500;
const storedBytesPerPeer = 8 * 1024 * 1024;
const storedBytesTotal = 64 * 1024 * 1024;
// Kept below what a 64 KB frame can carry so an oversized store is answered with
// an error instead of the whole signaling socket being closed at 1009.
const storedBlobMaxBytes = 40 * 1024;
const storedTtlMs = 7 * 24 * 60 * 60 * 1000;
const storedPurgeIntervalMs = 10 * 60 * 1000;

const allowedMessageTypes = new Set([
  'register',
  'blind_join',
  'blind_signal',
  'signal',
  'store',
]);
const peers = new Map();
const topics = new Map();
const queuedSignals = new Map();
const storedMessages = new Map();

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

function storedSizeBytes(entries) {
  return entries.reduce((total, entry) => total + entry.bytes, 0);
}

function purgeStored() {
  const now = Date.now();
  for (const [peerId, entries] of storedMessages) {
    const alive = entries.filter((entry) => entry.expiresAt > now);
    if (alive.length === 0) storedMessages.delete(peerId);
    else if (alive.length !== entries.length) storedMessages.set(peerId, alive);
  }
}

function totalStoredBytes() {
  let total = 0;
  for (const entries of storedMessages.values()) total += storedSizeBytes(entries);
  return total;
}

function evictOldestStored() {
  let oldestPeerId = null;
  let oldest = Infinity;
  for (const [peerId, entries] of storedMessages) {
    if (entries.length === 0) continue;
    if (entries[0].receivedAt < oldest) {
      oldest = entries[0].receivedAt;
      oldestPeerId = peerId;
    }
  }
  if (oldestPeerId === null) return false;
  const entries = storedMessages.get(oldestPeerId);
  entries.shift();
  if (entries.length === 0) storedMessages.delete(oldestPeerId);
  return true;
}

function storeMessage(to, from, messageId, blob) {
  const now = Date.now();
  const bytes = Math.floor((blob.length * 3) / 4);
  const entries = (storedMessages.get(to) || [])
    .filter((entry) => entry.expiresAt > now);
  // A sender that retries the same message must not make the peer decrypt it
  // twice, and the client already deduplicates by message id.
  if (entries.some((entry) => entry.messageId === messageId)) {
    return { stored: true, duplicate: true };
  }
  entries.push({ messageId, from, blob, bytes, receivedAt: now,
                 expiresAt: now + storedTtlMs });
  storedMessages.set(to, entries);
  while (entries.length > storedLimitPerPeer ||
         storedSizeBytes(entries) > storedBytesPerPeer) {
    entries.shift();
  }
  while (totalStoredBytes() > storedBytesTotal) {
    if (!evictOldestStored()) break;
  }
  if (entries.length === 0) storedMessages.delete(to);
  return { stored: true, duplicate: false };
}

function flushStoredMessages(peerId, socket) {
  const entries = storedMessages.get(peerId) || [];
  if (entries.length === 0) return;
  const now = Date.now();
  // Dropped one at a time: if the link dies partway through the rest are still
  // here for the next registration rather than lost with the socket.
  while (entries.length > 0 && socket.readyState === socket.OPEN) {
    const entry = entries.shift();
    if (entry.expiresAt <= now) continue;
    send(socket, {
      type: 'stored',
      from: entry.from,
      messageId: entry.messageId,
      blob: entry.blob,
    });
  }
  if (entries.length === 0) storedMessages.delete(peerId);
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

  const purgeTimer = setInterval(purgeStored, storedPurgeIntervalMs);
  purgeTimer.unref();
  server.on('close', () => clearInterval(purgeTimer));
  
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
      // The signature above was verified against the identity key that hashes to
      // this peer id, so this socket proves it owns the id. Refusing it instead
      // of taking over locked a device out of its own mailbox: a phone that lost
      // its socket on a network handover - routine on Android - could not
      // re-register until the 15-second heartbeat sweep freed the dead socket,
      // and in that window it neither collected its queue nor sent. The queue and
      // the pending signals are keyed by peer id, so nothing is lost here.
      const incumbent = peers.get(message.peerId);
      if (incumbent && incumbent !== socket) {
        incumbent.terminate();
        peers.delete(message.peerId);
      }
      removePeer(socket);
      clearTimeout(socket.registrationTimer);
      socket.peerId = message.peerId;
      socket.identityKey = message.identityKey;
      peers.set(message.peerId, socket);
      send(socket, { type: 'registered', peerId: message.peerId });
      flushQueuedSignals(message.peerId, socket);
      flushStoredMessages(message.peerId, socket);
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
      // A socket still listed but already closing accepts nothing, and `send`
      // drops silently - so the fallback queue is what keeps the signal alive
      // until the peer re-registers.
      if (recipient && recipient.readyState === recipient.OPEN) {
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

    if (message.type === 'store') {
      if (typeof socket.peerId !== 'string' ||
          typeof message.to !== 'string' ||
          message.to.length < 8 ||
          typeof message.messageId !== 'string' ||
          message.messageId.length > 128 ||
          typeof message.blob !== 'string' ||
          Math.floor((message.blob.length * 3) / 4) > storedBlobMaxBytes) {
        send(socket, { type: 'error', code: 'invalid_store' });
        return;
      }
      const recipient = peers.get(message.to);
      if (recipient && recipient.readyState === recipient.OPEN) {
        // Online: hand it over now instead of keeping a copy the sender has
        // already been told about.
        send(recipient, {
          type: 'stored',
          from: socket.peerId,
          messageId: message.messageId,
          blob: message.blob,
        });
        send(socket, {
          type: 'stored_ack',
          messageId: message.messageId,
          delivered: true,
        });
        return;
      }
      const result = storeMessage(
        message.to,
        socket.peerId,
        message.messageId,
        message.blob,
      );
      send(socket, {
        type: 'stored_ack',
        messageId: message.messageId,
        delivered: false,
        duplicate: result.duplicate,
      });
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
