import express from 'express';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const MEDIA_ROOT = path.resolve(__dirname, 'data', 'media');
const SESSIONS_DIR = path.resolve(MEDIA_ROOT, '.sessions');
const USERS_DIR = path.resolve(MEDIA_ROOT, 'users');

const IMAGE_FOLDERS = new Set([
  'profile',
  'cover',
  'posts',
  'pages',
  'groups',
  'story_photos',
  'events',
  'marketplace',
  'ads',
  'thumbnails',
]);
const VIDEO_FOLDERS = new Set(['videos', 'reels', 'story_videos', 'ad_videos']);
const ALLOWED_IMAGE_MIMES = new Set(['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif']);
const ALLOWED_VIDEO_MIMES = new Set(['video/mp4', 'video/webm', 'video/quicktime', 'video/x-m4v']);

const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const MAX_VIDEO_BYTES = 250 * 1024 * 1024;
const MAX_CHUNK_BYTES = 8 * 1024 * 1024;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

interface FirebaseClientConfig {
  projectId: string;
  apiKey: string;
  firestoreDatabaseId: string;
}

interface UploadSessionMeta {
  sessionId: string;
  uid: string;
  folder: string;
  fileName: string;
  contentType: string;
  mediaKind: 'photo' | 'video';
  totalBytes: number;
  uploadedBytes: number;
  createdAt: number;
  updatedAt: number;
}

interface VerifiedCaller {
  uid: string;
  emailVerified: boolean;
  idToken: string;
}

function loadFirebaseConfig(): FirebaseClientConfig {
  const configPath = path.resolve(__dirname, 'firebase-applet-config.json');
  const raw = fs.readFileSync(configPath, 'utf8');
  const parsed = JSON.parse(raw) as Partial<FirebaseClientConfig>;
  if (!parsed.projectId || !parsed.apiKey) {
    throw new Error('firebase-applet-config.json is missing projectId or apiKey.');
  }
  return {
    projectId: parsed.projectId,
    apiKey: parsed.apiKey,
    firestoreDatabaseId: parsed.firestoreDatabaseId || '(default)',
  };
}

const firebaseConfig = loadFirebaseConfig();

async function ensureDirectories(): Promise<void> {
  await fsp.mkdir(SESSIONS_DIR, { recursive: true });
  await fsp.mkdir(USERS_DIR, { recursive: true });
}

function isConfinedPath(baseDir: string, targetPath: string): boolean {
  const normalizedBase = path.resolve(baseDir);
  const normalizedTarget = path.resolve(targetPath);
  return normalizedTarget.startsWith(normalizedBase + path.sep);
}

function isValidSegment(value: string, pattern: RegExp): boolean {
  return Boolean(value) && pattern.test(value) && !value.includes('..');
}

function sanitizeFileName(rawName: string, mediaKind: 'photo' | 'video'): string {
  const base = path.basename(rawName || '').replace(/[^a-zA-Z0-9._-]/g, '_');
  const trimmed = base.replace(/^\.+/, '').slice(0, 80);
  if (!trimmed) {
    return mediaKind === 'video' ? 'video.mp4' : 'image.jpg';
  }
  return trimmed;
}

function decodeJwtPayload(token: string): { aud?: string; iss?: string; sub?: string } | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payloadJson = Buffer.from(parts[1], 'base64url').toString('utf8');
    return JSON.parse(payloadJson) as { aud?: string; iss?: string; sub?: string };
  } catch {
    return null;
  }
}

async function verifyFirebaseBearerToken(authHeader: string | undefined): Promise<VerifiedCaller | null> {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  const idToken = authHeader.slice('Bearer '.length).trim();
  if (!idToken || idToken.length > 8192) {
    return null;
  }

  const claims = decodeJwtPayload(idToken);
  if (
    !claims ||
    claims.aud !== firebaseConfig.projectId ||
    claims.iss !== `https://securetoken.google.com/${firebaseConfig.projectId}` ||
    !claims.sub
  ) {
    return null;
  }

  try {
    const res = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(firebaseConfig.apiKey)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken }),
      }
    );
    if (!res.ok) {
      return null;
    }
    const body = (await res.json()) as {
      users?: Array<{ localId?: string; emailVerified?: boolean; disabled?: boolean }>;
    };
    const user = body.users?.[0];
    if (!user?.localId || user.disabled) {
      return null;
    }
    if (user.localId !== claims.sub) {
      return null;
    }
    return {
      uid: user.localId,
      emailVerified: Boolean(user.emailVerified),
      idToken,
    };
  } catch (err) {
    console.error('[ASN MediaServer] Token verification failed:', err);
    return null;
  }
}

async function detectMagicMimeFromFile(
  filePath: string,
  mediaKind: 'photo' | 'video'
): Promise<string | null> {
  let fh: fsp.FileHandle | null = null;
  try {
    fh = await fsp.open(filePath, 'r');
    const buf = Buffer.alloc(16);
    const { bytesRead } = await fh.read(buf, 0, 16, 0);
    if (bytesRead < 4) return null;

    if (mediaKind === 'photo') {
      if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
      if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return 'image/png';
      if (buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x38) return 'image/gif';
      if (
        bytesRead >= 12 &&
        buf[0] === 0x52 &&
        buf[1] === 0x49 &&
        buf[2] === 0x46 &&
        buf[3] === 0x46 &&
        buf[8] === 0x57 &&
        buf[9] === 0x45 &&
        buf[10] === 0x42 &&
        buf[11] === 0x50
      ) {
        return 'image/webp';
      }
      return null;
    }

    if (buf[0] === 0x1a && buf[1] === 0x45 && buf[2] === 0xdf && buf[3] === 0xa3) {
      return 'video/webm';
    }
    if (
      bytesRead >= 12 &&
      buf[4] === 0x66 &&
      buf[5] === 0x74 &&
      buf[6] === 0x79 &&
      buf[7] === 0x70
    ) {
      const brand = buf.subarray(8, 12).toString('ascii');
      if (brand === 'qt  ') return 'video/quicktime';
      return 'video/mp4';
    }
    return null;
  } catch {
    return null;
  } finally {
    await fh?.close();
  }
}

function getMimeFromFilename(fileName: string): string {
  const ext = path.extname(fileName).toLowerCase();
  switch (ext) {
    case '.mp4':
    case '.m4v':
      return 'video/mp4';
    case '.mov':
      return 'video/quicktime';
    case '.webm':
      return 'video/webm';
    case '.jpg':
    case '.jpeg':
      return 'image/jpeg';
    case '.png':
      return 'image/png';
    case '.webp':
      return 'image/webp';
    case '.gif':
      return 'image/gif';
    default:
      return 'application/octet-stream';
  }
}

function getSessionPaths(sessionId: string): { metaPath: string; partPath: string } | null {
  if (!isValidSegment(sessionId, /^[a-f0-9]{24,64}$/)) {
    return null;
  }
  const metaPath = path.resolve(SESSIONS_DIR, `${sessionId}.json`);
  const partPath = path.resolve(SESSIONS_DIR, `${sessionId}.part`);
  if (!isConfinedPath(SESSIONS_DIR, metaPath) || !isConfinedPath(SESSIONS_DIR, partPath)) {
    return null;
  }
  return { metaPath, partPath };
}

async function readSessionMeta(sessionId: string): Promise<UploadSessionMeta | null> {
  const paths = getSessionPaths(sessionId);
  if (!paths) return null;
  try {
    const raw = await fsp.readFile(paths.metaPath, 'utf8');
    const meta = JSON.parse(raw) as UploadSessionMeta;
    if (Date.now() - meta.createdAt > SESSION_TTL_MS) {
      await removeSessionFiles(sessionId);
      return null;
    }
    return meta;
  } catch {
    return null;
  }
}

async function writeSessionMeta(meta: UploadSessionMeta): Promise<void> {
  const paths = getSessionPaths(meta.sessionId);
  if (!paths) {
    throw new Error('Invalid session identifier.');
  }
  await fsp.writeFile(paths.metaPath, JSON.stringify(meta), 'utf8');
}

async function removeSessionFiles(sessionId: string): Promise<void> {
  const paths = getSessionPaths(sessionId);
  if (!paths) return;
  await Promise.allSettled([fsp.rm(paths.metaPath, { force: true }), fsp.rm(paths.partPath, { force: true })]);
}

async function cleanupExpiredSessions(): Promise<void> {
  try {
    const entries = await fsp.readdir(SESSIONS_DIR);
    const now = Date.now();
    for (const entry of entries) {
      if (!entry.endsWith('.json')) continue;
      const sessionId = entry.slice(0, -5);
      const paths = getSessionPaths(sessionId);
      if (!paths) continue;
      try {
        const raw = await fsp.readFile(paths.metaPath, 'utf8');
        const meta = JSON.parse(raw) as UploadSessionMeta;
        if (now - meta.createdAt > SESSION_TTL_MS) {
          await removeSessionFiles(sessionId);
        }
      } catch {
        await removeSessionFiles(sessionId);
      }
    }
  } catch {
    // Non-blocking background cleanup
  }
}

function getSafeMediaFilePath(userId: string, folder: string, fileName: string): string | null {
  if (
    !isValidSegment(userId, /^[a-zA-Z0-9_-]{3,128}$/) ||
    (!IMAGE_FOLDERS.has(folder) && !VIDEO_FOLDERS.has(folder)) ||
    !isValidSegment(fileName, /^[a-zA-Z0-9._-]{1,120}$/)
  ) {
    return null;
  }
  const targetPath = path.resolve(USERS_DIR, userId, folder, fileName);
  if (!isConfinedPath(USERS_DIR, targetPath)) {
    return null;
  }
  return targetPath;
}

async function createMediaRouter(): Promise<express.Router> {
  await ensureDirectories();
  void cleanupExpiredSessions();

  const router = express.Router();

  // Initialize a resumable upload session (authenticated owner only)
  router.post('/uploads/init', express.json({ limit: '32kb' }), async (req, res) => {
    const caller = await verifyFirebaseBearerToken(req.headers.authorization);
    if (!caller) {
      res.status(401).json({ error: 'Authentication required to upload media.' });
      return;
    }

    const body = (req.body || {}) as Record<string, unknown>;
    const uid = typeof body.uid === 'string' ? body.uid.trim() : '';
    const folder = typeof body.folder === 'string' ? body.folder.trim() : '';
    const rawFileName = typeof body.fileName === 'string' ? body.fileName.trim() : '';
    const rawContentType = typeof body.contentType === 'string' ? body.contentType.trim().toLowerCase() : '';
    const totalBytes = typeof body.totalBytes === 'number' ? Math.floor(body.totalBytes) : 0;

    if (!uid || uid !== caller.uid || !isValidSegment(uid, /^[a-zA-Z0-9_-]{3,128}$/)) {
      res.status(403).json({ error: 'You can only upload media to your own account.' });
      return;
    }

    const isPhotoFolder = IMAGE_FOLDERS.has(folder);
    const isVideoFolder = VIDEO_FOLDERS.has(folder);
    if (!isPhotoFolder && !isVideoFolder) {
      res.status(400).json({ error: 'Invalid media destination folder.' });
      return;
    }

    const mediaKind: 'photo' | 'video' = isVideoFolder ? 'video' : 'photo';
    const maxBytes = mediaKind === 'video' ? MAX_VIDEO_BYTES : MAX_IMAGE_BYTES;
    const allowedMimes = mediaKind === 'video' ? ALLOWED_VIDEO_MIMES : ALLOWED_IMAGE_MIMES;

    if (!allowedMimes.has(rawContentType)) {
      res.status(400).json({
        error:
          mediaKind === 'video'
            ? 'Unsupported video format. Please choose an MP4, MOV, or WebM video.'
            : 'Unsupported photo format. Please choose a JPEG, PNG, WebP, or GIF image.',
      });
      return;
    }

    if (!Number.isFinite(totalBytes) || totalBytes <= 0 || totalBytes > maxBytes) {
      res.status(400).json({
        error:
          mediaKind === 'video'
            ? 'Video is too large. Maximum allowed size is 250 MB.'
            : 'Image is too large. Maximum allowed size is 5 MB.',
      });
      return;
    }

    const sessionId = crypto.randomBytes(16).toString('hex');
    const safeFileName = `${Date.now()}_${sanitizeFileName(rawFileName, mediaKind)}`.slice(0, 110);
    const paths = getSessionPaths(sessionId);
    if (!paths) {
      res.status(500).json({ error: 'Unable to initialize upload session.' });
      return;
    }

    const meta: UploadSessionMeta = {
      sessionId,
      uid,
      folder,
      fileName: safeFileName,
      contentType: rawContentType,
      mediaKind,
      totalBytes,
      uploadedBytes: 0,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };

    try {
      await fsp.writeFile(paths.partPath, Buffer.alloc(0));
      await writeSessionMeta(meta);
      res.status(201).json({
        sessionId,
        uploadedBytes: 0,
        totalBytes,
        chunkSize: 2 * 1024 * 1024,
      });
    } catch (err) {
      console.error('[ASN MediaServer] Failed to initialize session:', err);
      await removeSessionFiles(sessionId);
      res.status(500).json({ error: 'Unable to initialize upload session.' });
    }
  });

  // Query resumable upload status (for genuine Retry resume from last committed offset)
  router.get('/uploads/:sessionId', async (req, res) => {
    const caller = await verifyFirebaseBearerToken(req.headers.authorization);
    if (!caller) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }
    const meta = await readSessionMeta(req.params.sessionId);
    if (!meta) {
      res.status(404).json({ error: 'Upload session expired or not found.' });
      return;
    }
    if (meta.uid !== caller.uid) {
      res.status(403).json({ error: 'Access denied.' });
      return;
    }
    const paths = getSessionPaths(meta.sessionId);
    if (!paths) {
      res.status(404).json({ error: 'Upload session not found.' });
      return;
    }
    try {
      const stat = await fsp.stat(paths.partPath);
      const committedBytes = Math.min(stat.size, meta.uploadedBytes);
      if (committedBytes !== meta.uploadedBytes) {
        meta.uploadedBytes = committedBytes;
        meta.updatedAt = Date.now();
        await writeSessionMeta(meta);
      }
      res.json({
        sessionId: meta.sessionId,
        uploadedBytes: committedBytes,
        totalBytes: meta.totalBytes,
      });
    } catch {
      res.status(404).json({ error: 'Upload session data missing.' });
    }
  });

  // Upload binary chunk sequentially and finalize when complete
  router.put(
    '/uploads/:sessionId',
    express.raw({ type: 'application/octet-stream', limit: MAX_CHUNK_BYTES }),
    async (req, res) => {
      const caller = await verifyFirebaseBearerToken(req.headers.authorization);
      if (!caller) {
        res.status(401).json({ error: 'Authentication required.' });
        return;
      }

      const meta = await readSessionMeta(req.params.sessionId);
      if (!meta) {
        res.status(404).json({ error: 'Upload session expired or not found.' });
        return;
      }
      if (meta.uid !== caller.uid) {
        res.status(403).json({ error: 'You do not have permission to upload to this session.' });
        return;
      }

      const paths = getSessionPaths(meta.sessionId);
      if (!paths) {
        res.status(404).json({ error: 'Upload session invalid.' });
        return;
      }

      const offsetHeader = req.headers['x-upload-offset'];
      const offset = Number(Array.isArray(offsetHeader) ? offsetHeader[0] : offsetHeader);
      if (!Number.isInteger(offset) || offset < 0) {
        res.status(400).json({ error: 'Missing or invalid upload byte offset.' });
        return;
      }

      const chunk = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
      if (chunk.length === 0) {
        res.status(400).json({ error: 'Empty upload chunk.' });
        return;
      }

      const stat = await fsp.stat(paths.partPath).catch(() => null);
      if (!stat) {
        res.status(404).json({ error: 'Upload session buffer not found.' });
        return;
      }

      if (offset !== stat.size) {
        res.status(409).json({
          error: 'Chunk offset mismatch. Resume from server offset.',
          uploadedBytes: stat.size,
        });
        return;
      }

      const nextSize = offset + chunk.length;
      if (nextSize > meta.totalBytes) {
        res.status(400).json({ error: 'Upload exceeds declared file size.' });
        return;
      }

      try {
        await fsp.appendFile(paths.partPath, chunk);
        meta.uploadedBytes = nextSize;
        meta.updatedAt = Date.now();
        await writeSessionMeta(meta);
      } catch (err) {
        console.error('[ASN MediaServer] Failed writing upload chunk:', err);
        res.status(500).json({ error: 'Failed to save upload chunk.' });
        return;
      }

      if (nextSize < meta.totalBytes) {
        res.status(200).json({
          completed: false,
          uploadedBytes: nextSize,
          totalBytes: meta.totalBytes,
        });
        return;
      }

      // Final chunk received — verify file signature magic bytes before publishing
      const detectedMime = await detectMagicMimeFromFile(paths.partPath, meta.mediaKind);
      if (!detectedMime) {
        await removeSessionFiles(meta.sessionId);
        res.status(400).json({
          error:
            meta.mediaKind === 'video'
              ? 'File contents do not match a supported MP4, MOV, or WebM video.'
              : 'File contents do not match a supported JPEG, PNG, WebP, or GIF image.',
        });
        return;
      }

      const destPath = getSafeMediaFilePath(meta.uid, meta.folder, meta.fileName);
      if (!destPath) {
        await removeSessionFiles(meta.sessionId);
        res.status(400).json({ error: 'Invalid destination path.' });
        return;
      }

      try {
        await fsp.mkdir(path.dirname(destPath), { recursive: true });
        await fsp.rename(paths.partPath, destPath);
        await fsp.rm(paths.metaPath, { force: true });
        const publicUrl = `/api/media/files/${encodeURIComponent(meta.uid)}/${encodeURIComponent(meta.folder)}/${encodeURIComponent(meta.fileName)}`;
        res.status(201).json({
          completed: true,
          uploadedBytes: nextSize,
          totalBytes: meta.totalBytes,
          url: publicUrl,
          contentType: detectedMime,
        });
      } catch (err) {
        console.error('[ASN MediaServer] Failed finalizing uploaded media:', err);
        await removeSessionFiles(meta.sessionId);
        res.status(500).json({ error: 'Unable to finalize uploaded file.' });
      }
    }
  );

  // Cancel and discard an in-progress upload session
  router.delete('/uploads/:sessionId', async (req, res) => {
    const caller = await verifyFirebaseBearerToken(req.headers.authorization);
    if (!caller) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }
    const meta = await readSessionMeta(req.params.sessionId);
    if (!meta) {
      res.status(204).end();
      return;
    }
    if (meta.uid !== caller.uid) {
      res.status(403).json({ error: 'Access denied.' });
      return;
    }
    await removeSessionFiles(meta.sessionId);
    res.status(204).end();
  });

  // Delete an owned uploaded file (used when replacing cover photos or deleting posts)
  router.delete('/files/:userId/:folder/:fileName', async (req, res) => {
    const caller = await verifyFirebaseBearerToken(req.headers.authorization);
    if (!caller) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }
    const { userId, folder, fileName } = req.params;
    if (caller.uid !== userId) {
      res.status(403).json({ error: 'You can only delete your own media files.' });
      return;
    }
    const filePath = getSafeMediaFilePath(userId, folder, fileName);
    if (!filePath) {
      res.status(400).json({ error: 'Invalid file path.' });
      return;
    }
    await fsp.rm(filePath, { force: true });
    res.status(204).end();
  });

  // Serve uploaded photos & videos with HTTP Range (206 Partial Content) streaming
  router.get('/files/:userId/:folder/:fileName', async (req, res) => {
    const { userId, folder, fileName } = req.params;
    const filePath = getSafeMediaFilePath(userId, folder, fileName);
    if (!filePath) {
      res.status(404).end();
      return;
    }

    const stat = await fsp.stat(filePath).catch(() => null);
    if (!stat || !stat.isFile()) {
      res.status(404).end();
      return;
    }

    const total = stat.size;
    const mediaKind: 'photo' | 'video' = VIDEO_FOLDERS.has(folder) ? 'video' : 'photo';
    const inferredMime =
      (await detectMagicMimeFromFile(filePath, mediaKind)) || getMimeFromFilename(fileName);

    res.setHeader('Content-Type', inferredMime);
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');

    const rangeHeader = req.headers.range;
    if (rangeHeader && typeof rangeHeader === 'string' && rangeHeader.startsWith('bytes=')) {
      const [rawStart, rawEnd] = rangeHeader.replace(/^bytes=/, '').split('-');
      const start = rawStart ? Number.parseInt(rawStart, 10) : 0;
      const end = rawEnd ? Math.min(total - 1, Number.parseInt(rawEnd, 10)) : total - 1;

      if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || start > end || start >= total) {
        res.status(416).setHeader('Content-Range', `bytes */${total}`).end();
        return;
      }

      res.status(206);
      res.setHeader('Content-Range', `bytes ${start}-${end}/${total}`);
      res.setHeader('Content-Length', String(end - start + 1));

      if (req.method === 'HEAD') {
        res.end();
        return;
      }

      const stream = fs.createReadStream(filePath, { start, end });
      stream.on('error', () => {
        if (!res.headersSent) res.status(500);
        res.end();
      });
      stream.pipe(res);
      return;
    }

    res.status(200);
    res.setHeader('Content-Length', String(total));
    if (req.method === 'HEAD') {
      res.end();
      return;
    }

    const stream = fs.createReadStream(filePath);
    stream.on('error', () => {
      if (!res.headersSent) res.status(500);
      res.end();
    });
    stream.pipe(res);
  });

  return router;
}

interface EmailOtpChallenge {
  salt: string;
  hmacDigest: string;
  expiresAt: number;
  lastSentAt: number;
  attempts: number;
}

const OTP_SIGNING_SECRET = process.env.OTP_SIGNING_SECRET || crypto.randomBytes(32).toString('hex');
const emailOtpStore = new Map<string, EmailOtpChallenge>();
const emailOtpWindow = new Map<string, number[]>();

function computeOtpDigest(salt: string, email: string, code: string): string {
  return crypto
    .createHmac('sha256', OTP_SIGNING_SECRET)
    .update(`${salt}:${email}:${code}`)
    .digest('hex');
}

function createAuthVerificationRouter(): express.Router {
  const router = express.Router();

  router.post('/email-otp/send', express.json({ limit: '16kb' }), async (req, res) => {
    const body = (req.body || {}) as Record<string, unknown>;
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
      res.status(400).json({ error: 'Please enter a valid email address.' });
      return;
    }

    const resendApiKey = (process.env.RESEND_API_KEY || '').trim();
    const emailFrom = (process.env.EMAIL_FROM || '').trim();
    if (!resendApiKey || !emailFrom) {
      res.json({ deliveryMode: 'firebase_link' });
      return;
    }

    const now = Date.now();
    const prevSends = (emailOtpWindow.get(email) || []).filter((ts) => now - ts < 15 * 60 * 1000);
    if (prevSends.length >= 5) {
      res.status(429).json({ error: 'Too many verification code requests. Please try again later.' });
      return;
    }

    const existing = emailOtpStore.get(email);
    if (existing && now - existing.lastSentAt < 30_000) {
      const waitSec = Math.ceil((30_000 - (now - existing.lastSentAt)) / 1000);
      res.status(429).json({ error: `Please wait ${waitSec}s before requesting another code.` });
      return;
    }

    const code = String(crypto.randomInt(100000, 1000000));
    const salt = crypto.randomBytes(16).toString('hex');
    const hmacDigest = computeOtpDigest(salt, email, code);

    try {
      const mailRes = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${resendApiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: emailFrom,
          to: [email],
          subject: 'Your ASN Social Network Verification Code',
          text: `Your ASN Social Network verification code is ${code}. It expires in 10 minutes. If you did not request this, you can safely ignore this email.`,
        }),
      });

      if (!mailRes.ok) {
        res.status(502).json({ error: 'Unable to send verification email right now. Please try again.' });
        return;
      }

      prevSends.push(now);
      emailOtpWindow.set(email, prevSends);
      emailOtpStore.set(email, {
        salt,
        hmacDigest,
        expiresAt: now + 10 * 60 * 1000,
        lastSentAt: now,
        attempts: 0,
      });

      res.json({ deliveryMode: 'otp', expiresInSeconds: 600 });
    } catch (err) {
      console.error('[ASN Auth] Email OTP dispatch failed:', err);
      res.status(502).json({ error: 'Unable to send verification email right now.' });
    }
  });

  router.post('/email-otp/verify', express.json({ limit: '16kb' }), (req, res) => {
    const body = (req.body || {}) as Record<string, unknown>;
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const code = typeof body.code === 'string' ? body.code.trim() : '';

    if (!email || !/^\d{6}$/.test(code)) {
      res.status(400).json({ error: 'Enter the 6-digit verification code sent to your email.' });
      return;
    }

    const challenge = emailOtpStore.get(email);
    if (!challenge || Date.now() > challenge.expiresAt) {
      emailOtpStore.delete(email);
      res.status(400).json({ error: 'Verification code expired or not requested. Tap Resend Code.' });
      return;
    }

    if (challenge.attempts >= 5) {
      emailOtpStore.delete(email);
      res.status(429).json({ error: 'Too many incorrect attempts. Please request a new code.' });
      return;
    }

    const expectedBuf = Buffer.from(challenge.hmacDigest, 'hex');
    const actualBuf = Buffer.from(computeOtpDigest(challenge.salt, email, code), 'hex');
    const matches =
      expectedBuf.length === actualBuf.length && crypto.timingSafeEqual(expectedBuf, actualBuf);

    if (!matches) {
      challenge.attempts += 1;
      res.status(400).json({ error: 'Incorrect verification code. Please check your email and try again.' });
      return;
    }

    emailOtpStore.delete(email);
    res.json({ verified: true });
  });

  return router;
}

type FsValue =
  | { stringValue: string }
  | { integerValue: string }
  | { booleanValue: boolean }
  | { timestampValue: string }
  | { nullValue: null }
  | { arrayValue: { values?: FsValue[] } }
  | { mapValue: { fields?: Record<string, FsValue> } };

function encodeFsValue(value: unknown): FsValue {
  if (value === null || value === undefined) return { nullValue: null };
  if (typeof value === 'string') return { stringValue: value };
  if (typeof value === 'boolean') return { booleanValue: value };
  if (typeof value === 'number' && Number.isInteger(value)) {
    return { integerValue: String(value) };
  }
  if (Array.isArray(value)) {
    return { arrayValue: { values: value.map((v) => encodeFsValue(v)) } };
  }
  if (typeof value === 'object') {
    const fields: Record<string, FsValue> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (v !== undefined) {
        fields[k] = encodeFsValue(v);
      }
    }
    return { mapValue: { fields } };
  }
  return { stringValue: String(value) };
}

function decodeFsValue(val: FsValue | undefined): unknown {
  if (!val) return undefined;
  if ('stringValue' in val) return val.stringValue;
  if ('booleanValue' in val) return val.booleanValue;
  if ('integerValue' in val) return Number.parseInt(val.integerValue, 10);
  if ('timestampValue' in val) return val.timestampValue;
  if ('nullValue' in val) return null;
  if ('arrayValue' in val) {
    return (val.arrayValue.values || []).map((item) => decodeFsValue(item));
  }
  if ('mapValue' in val) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(val.mapValue.fields || {})) {
      out[k] = decodeFsValue(v);
    }
    return out;
  }
  return undefined;
}

function decodeFsDoc(fields: Record<string, FsValue> | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (!fields) return out;
  for (const [k, v] of Object.entries(fields)) {
    out[k] = decodeFsValue(v);
  }
  return out;
}

function getFirestoreBaseUrl(): string {
  return `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(firebaseConfig.projectId)}/databases/${encodeURIComponent(firebaseConfig.firestoreDatabaseId)}`;
}

function fsDocPath(relPath: string): string {
  return `projects/${firebaseConfig.projectId}/databases/${firebaseConfig.firestoreDatabaseId}/documents/${relPath}`;
}

async function fsGetDoc(relPath: string, idToken: string): Promise<Record<string, unknown> | null> {
  const res = await fetch(`${getFirestoreBaseUrl()}/documents/${relPath}`, {
    headers: { Authorization: `Bearer ${idToken}` },
  });
  if (res.status === 404) return null;
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Firestore read failed (${res.status}): ${text.slice(0, 200)}`);
  }
  const json = (await res.json()) as { fields?: Record<string, FsValue> };
  return decodeFsDoc(json.fields);
}

interface FsCommitWrite {
  update?: { name: string; fields: Record<string, FsValue> };
  updateMask?: { fieldPaths: string[] };
  updateTransforms?: Array<{ fieldPath: string; setToServerValue: 'REQUEST_TIME' }>;
  delete?: string;
}

async function fsCommit(writes: FsCommitWrite[], idToken: string): Promise<void> {
  const res = await fetch(`${getFirestoreBaseUrl()}/documents:commit`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${idToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ writes }),
  });
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    const status = res.status;
    const msg = status === 403 ? 'You do not have permission to perform this page action.' : `Unable to save page changes (${status}).`;
    const err = new Error(msg) as Error & { statusCode?: number; detail?: string };
    err.statusCode = status;
    err.detail = errText.slice(0, 400);
    throw err;
  }
}

type ServerPageRole = 'owner' | 'admin' | 'editor' | 'moderator';

function resolveServerPageRole(
  page: Record<string, unknown>,
  member: Record<string, unknown> | null,
  uid: string
): { role: ServerPageRole | null; canManageMembers: boolean; originalOwnerId: string } {
  const ownerId = typeof page.ownerId === 'string' ? page.ownerId : '';
  const originalOwnerId =
    typeof page.originalOwnerId === 'string' && page.originalOwnerId ? page.originalOwnerId : ownerId;
  if (uid === ownerId || uid === originalOwnerId) {
    return { role: 'owner', canManageMembers: true, originalOwnerId };
  }
  if (member && member.status === 'active') {
    const r = String(member.role || '');
    if (r === 'owner') return { role: 'owner', canManageMembers: true, originalOwnerId };
    if (r === 'admin') {
      return {
        role: 'admin',
        canManageMembers: Boolean(member.canManageMembers),
        originalOwnerId,
      };
    }
    if (r === 'editor' || r === 'moderator') {
      return { role: r, canManageMembers: false, originalOwnerId };
    }
  }
  const managerIds = Array.isArray(page.managerIds) ? page.managerIds : [];
  if (managerIds.includes(uid)) {
    return { role: 'admin', canManageMembers: false, originalOwnerId };
  }
  return { role: null, canManageMembers: false, originalOwnerId };
}

function createPageAccessRouter(): express.Router {
  const router = express.Router();
  const idPattern = /^[a-zA-Z0-9_-]{1,128}$/;

  // Verify whether caller has active access to switch into the requested Page
  router.post('/:pageId/verify-switch', async (req, res) => {
    const caller = await verifyFirebaseBearerToken(req.headers.authorization);
    if (!caller) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }
    const { pageId } = req.params;
    if (!isValidSegment(pageId, idPattern)) {
      res.status(400).json({ error: 'Invalid page ID.' });
      return;
    }
    try {
      const [page, member] = await Promise.all([
        fsGetDoc(`pages/${pageId}`, caller.idToken),
        fsGetDoc(`pages/${pageId}/members/${caller.uid}`, caller.idToken),
      ]);
      if (!page || page.status !== 'active') {
        res.status(404).json({ error: 'Page not found or inactive.' });
        return;
      }
      const resolved = resolveServerPageRole(page, member, caller.uid);
      if (!resolved.role) {
        res.status(403).json({ error: 'You do not have active access to this page.' });
        return;
      }
      res.json({
        authorized: true,
        role: resolved.role,
        canManageMembers: resolved.canManageMembers,
      });
    } catch (err) {
      console.error('[ASN PageServer] verify-switch failed:', err);
      res.status(500).json({ error: 'Unable to verify page access right now.' });
    }
  });

  // Invite a user to a Page with an explicit role (Owner or Full Access Admin with manage rights)
  router.post('/:pageId/invitations', express.json({ limit: '16kb' }), async (req, res) => {
    const caller = await verifyFirebaseBearerToken(req.headers.authorization);
    if (!caller) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }
    const { pageId } = req.params;
    const body = (req.body || {}) as Record<string, unknown>;
    const targetUid = typeof body.targetUid === 'string' ? body.targetUid.trim() : '';
    const role = typeof body.role === 'string' ? body.role.trim() : '';
    const canManageMembers = role === 'admin' && Boolean(body.canManageMembers);

    if (!isValidSegment(pageId, idPattern) || !isValidSegment(targetUid, idPattern)) {
      res.status(400).json({ error: 'Invalid page or user identifier.' });
      return;
    }
    if (targetUid.startsWith('page_') || targetUid === pageId) {
      res.status(400).json({ error: 'Page access can only be sent to a personal profile, not a page.' });
      return;
    }
    if (role !== 'admin' && role !== 'editor' && role !== 'moderator') {
      res.status(400).json({ error: 'Choose Admin, Editor, or Moderator access level.' });
      return;
    }

    try {
      const [page, callerMember, actorPub, targetPub, targetPageDoc, targetMember] = await Promise.all([
        fsGetDoc(`pages/${pageId}`, caller.idToken),
        fsGetDoc(`pages/${pageId}/members/${caller.uid}`, caller.idToken),
        fsGetDoc(`users_public/${caller.uid}`, caller.idToken),
        fsGetDoc(`users_public/${targetUid}`, caller.idToken),
        fsGetDoc(`pages/${targetUid}`, caller.idToken),
        fsGetDoc(`pages/${pageId}/members/${targetUid}`, caller.idToken),
      ]);

      if (targetPageDoc) {
        res.status(400).json({ error: 'Page access can only be sent to a personal profile, not a page.' });
        return;
      }
      if (!page || page.status !== 'active') {
        res.status(404).json({ error: 'Page not found.' });
        return;
      }
      const resolved = resolveServerPageRole(page, callerMember, caller.uid);
      if (!resolved.role || (resolved.role !== 'owner' && !(resolved.role === 'admin' && resolved.canManageMembers))) {
        res.status(403).json({ error: 'Only the Page Owner or authorized Admins can invite members.' });
        return;
      }
      if (targetUid === resolved.originalOwnerId || targetUid === caller.uid) {
        res.status(400).json({ error: 'Cannot invite the page owner or yourself.' });
        return;
      }
      if (!targetPub || targetPub.accountStatus !== 'active') {
        res.status(404).json({ error: 'Selected user profile was not found.' });
        return;
      }
      if (targetMember && targetMember.status === 'active') {
        res.status(409).json({ error: 'This user already has access to this page. Update their role instead.' });
        return;
      }

      const actorName = String(actorPub?.displayName || 'Page Admin').slice(0, 60);
      const actorPhoto = String(actorPub?.photoURL || '');
      const inviteeName = String(targetPub.displayName || 'ASN User').slice(0, 60);
      const inviteeUsername = String(targetPub.username || 'member').slice(0, 24);
      const inviteePhoto = String(targetPub.photoURL || '');
      const pageName = String(page.name || 'ASN Page').slice(0, 80);
      const pageHandle = String(page.handle || 'asn_page').slice(0, 30);
      const pageAvatar = String(page.avatarURL || '');

      const invitePayload = {
        pageId,
        pageName,
        pageHandle,
        pageAvatarURL: pageAvatar,
        pageOwnerId: resolved.originalOwnerId,
        inviteeId: targetUid,
        inviteeName,
        inviteeUsername,
        inviteePhotoURL: inviteePhoto,
        invitedById: caller.uid,
        invitedByName: actorName,
        role,
        canManageMembers,
        status: 'pending',
      };
      const inviteFields: Record<string, FsValue> = {};
      for (const [k, v] of Object.entries(invitePayload)) {
        inviteFields[k] = encodeFsValue(v);
      }

      const logId = `log_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
      const notifId = `notif_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
      const pageNotifId = `pnotif_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
      const roleLabel =
        role === 'admin'
          ? canManageMembers
            ? 'Full Access Admin (can manage members)'
            : 'Full Access Admin'
          : role === 'editor'
          ? 'Limited Access Editor'
          : 'Moderator';

      const writes: FsCommitWrite[] = [
        {
          update: { name: fsDocPath(`pages/${pageId}/invitations/${targetUid}`), fields: inviteFields },
          updateTransforms: [
            { fieldPath: 'createdAt', setToServerValue: 'REQUEST_TIME' },
            { fieldPath: 'updatedAt', setToServerValue: 'REQUEST_TIME' },
          ],
        },
        {
          update: { name: fsDocPath(`users_public/${targetUid}/page_invites/${pageId}`), fields: inviteFields },
          updateTransforms: [
            { fieldPath: 'createdAt', setToServerValue: 'REQUEST_TIME' },
            { fieldPath: 'updatedAt', setToServerValue: 'REQUEST_TIME' },
          ],
        },
        {
          update: {
            name: fsDocPath(`pages/${pageId}/audit_logs/${logId}`),
            fields: {
              pageId: encodeFsValue(pageId),
              action: encodeFsValue('invite_sent'),
              actorId: encodeFsValue(caller.uid),
              actorName: encodeFsValue(actorName),
              actorRole: encodeFsValue(resolved.role),
              targetUserId: encodeFsValue(targetUid),
              targetUserName: encodeFsValue(inviteeName),
              previousRole: encodeFsValue('none'),
              newRole: encodeFsValue(role),
              details: encodeFsValue(`${actorName} invited ${inviteeName} as ${roleLabel}.`),
            },
          },
          updateTransforms: [{ fieldPath: 'createdAt', setToServerValue: 'REQUEST_TIME' }],
        },
        {
          update: {
            name: fsDocPath(`pages/${pageId}/notifications/${pageNotifId}`),
            fields: {
              pageId: encodeFsValue(pageId),
              actorId: encodeFsValue(caller.uid),
              actorName: encodeFsValue(actorName),
              actorPhotoURL: encodeFsValue(actorPhoto),
              type: encodeFsValue('access_invite'),
              targetId: encodeFsValue(targetUid),
              message: encodeFsValue(`${actorName} invited ${inviteeName} as ${roleLabel}.`),
              read: encodeFsValue(false),
            },
          },
          updateTransforms: [{ fieldPath: 'createdAt', setToServerValue: 'REQUEST_TIME' }],
        },
      ];

      await fsCommit(writes, caller.idToken);

      // Best-effort user notification (requires canAct on notifications, so non-blocking)
      try {
        await fsCommit(
          [
            {
              update: {
                name: fsDocPath(`notifications/${notifId}`),
                fields: {
                  recipientId: encodeFsValue(targetUid),
                  actorId: encodeFsValue(caller.uid),
                  actorName: encodeFsValue(actorName),
                  actorPhotoURL: encodeFsValue(actorPhoto),
                  type: encodeFsValue('page_invite'),
                  targetId: encodeFsValue(pageId),
                  message: encodeFsValue(
                    `${actorName} invited you to help manage "${pageName}" as ${roleLabel}.`
                  ),
                  read: encodeFsValue(false),
                },
              },
              updateTransforms: [{ fieldPath: 'createdAt', setToServerValue: 'REQUEST_TIME' }],
            },
          ],
          caller.idToken
        );
      } catch {
        // Non-blocking notification
      }

      res.status(201).json({ ok: true });
    } catch (err) {
      const code = (err as { statusCode?: number }).statusCode || 500;
      console.error('[ASN PageServer] create invitation failed:', err);
      res.status(code === 403 ? 403 : 400).json({
        error: err instanceof Error ? err.message : 'Unable to send page invitation.',
      });
    }
  });

  // Accept or decline a pending Page invitation (invitee only)
  router.post('/:pageId/invitations/respond', express.json({ limit: '16kb' }), async (req, res) => {
    const caller = await verifyFirebaseBearerToken(req.headers.authorization);
    if (!caller) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }
    const { pageId } = req.params;
    const body = (req.body || {}) as Record<string, unknown>;
    const decision = body.decision === 'accepted' ? 'accepted' : body.decision === 'declined' ? 'declined' : null;
    if (!isValidSegment(pageId, idPattern) || !decision) {
      res.status(400).json({ error: 'Invalid invitation response.' });
      return;
    }

    try {
      const [page, invite, callerPub] = await Promise.all([
        fsGetDoc(`pages/${pageId}`, caller.idToken),
        fsGetDoc(`pages/${pageId}/invitations/${caller.uid}`, caller.idToken),
        fsGetDoc(`users_public/${caller.uid}`, caller.idToken),
      ]);

      if (!page || !invite || invite.status !== 'pending' || invite.inviteeId !== caller.uid) {
        res.status(404).json({ error: 'Pending invitation not found or already handled.' });
        return;
      }

      const displayName = String(callerPub?.displayName || invite.inviteeName || 'ASN User').slice(0, 60);
      const username = String(callerPub?.username || invite.inviteeUsername || 'member').slice(0, 24);
      const photoURL = String(callerPub?.photoURL || invite.inviteePhotoURL || '');
      const role = String(invite.role || 'editor');
      const canManageMembers = role === 'admin' && Boolean(invite.canManageMembers);
      const logId = `log_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
      const pNotifId = `pnotif_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;

      const writes: FsCommitWrite[] = [
        {
          update: {
            name: fsDocPath(`pages/${pageId}/invitations/${caller.uid}`),
            fields: { status: encodeFsValue(decision) },
          },
          updateMask: { fieldPaths: ['status', 'updatedAt'] },
          updateTransforms: [{ fieldPath: 'updatedAt', setToServerValue: 'REQUEST_TIME' }],
        },
        {
          update: {
            name: fsDocPath(`users_public/${caller.uid}/page_invites/${pageId}`),
            fields: { status: encodeFsValue(decision) },
          },
          updateMask: { fieldPaths: ['status', 'updatedAt'] },
          updateTransforms: [{ fieldPath: 'updatedAt', setToServerValue: 'REQUEST_TIME' }],
        },
        {
          update: {
            name: fsDocPath(`pages/${pageId}/audit_logs/${logId}`),
            fields: {
              pageId: encodeFsValue(pageId),
              action: encodeFsValue(decision === 'accepted' ? 'invite_accepted' : 'invite_declined'),
              actorId: encodeFsValue(caller.uid),
              actorName: encodeFsValue(displayName),
              actorRole: encodeFsValue('invitee'),
              targetUserId: encodeFsValue(caller.uid),
              targetUserName: encodeFsValue(displayName),
              previousRole: encodeFsValue('none'),
              newRole: encodeFsValue(decision === 'accepted' ? role : 'declined'),
              details: encodeFsValue(
                decision === 'accepted'
                  ? `${displayName} accepted invitation as ${role}.`
                  : `${displayName} declined page invitation.`
              ),
            },
          },
          updateTransforms: [{ fieldPath: 'createdAt', setToServerValue: 'REQUEST_TIME' }],
        },
        {
          update: {
            name: fsDocPath(`pages/${pageId}/notifications/${pNotifId}`),
            fields: {
              pageId: encodeFsValue(pageId),
              actorId: encodeFsValue(caller.uid),
              actorName: encodeFsValue(displayName),
              actorPhotoURL: encodeFsValue(photoURL),
              type: encodeFsValue('access_update'),
              targetId: encodeFsValue(caller.uid),
              message: encodeFsValue(
                decision === 'accepted'
                  ? `${displayName} accepted Page Access (${role}).`
                  : `${displayName} declined Page Access invitation.`
              ),
              read: encodeFsValue(false),
            },
          },
          updateTransforms: [{ fieldPath: 'createdAt', setToServerValue: 'REQUEST_TIME' }],
        },
      ];

      if (decision === 'accepted') {
        writes.unshift({
          update: {
            name: fsDocPath(`pages/${pageId}/members/${caller.uid}`),
            fields: {
              pageId: encodeFsValue(pageId),
              userId: encodeFsValue(caller.uid),
              displayName: encodeFsValue(displayName),
              username: encodeFsValue(username),
              photoURL: encodeFsValue(photoURL),
              role: encodeFsValue(role),
              canManageMembers: encodeFsValue(canManageMembers),
              status: encodeFsValue('active'),
              invitedBy: encodeFsValue(String(invite.invitedById || page.ownerId || caller.uid)),
            },
          },
          updateTransforms: [
            { fieldPath: 'createdAt', setToServerValue: 'REQUEST_TIME' },
            { fieldPath: 'updatedAt', setToServerValue: 'REQUEST_TIME' },
          ],
        });
      }

      await fsCommit(writes, caller.idToken);
      res.json({ ok: true, decision });
    } catch (err) {
      const code = (err as { statusCode?: number }).statusCode || 500;
      console.error('[ASN PageServer] invitation respond failed:', err);
      res.status(code === 403 ? 403 : 400).json({
        error: err instanceof Error ? err.message : 'Unable to respond to invitation.',
      });
    }
  });

  // Update an existing active member's role (cannot target Original Owner)
  router.patch('/:pageId/members/:targetUid', express.json({ limit: '16kb' }), async (req, res) => {
    const caller = await verifyFirebaseBearerToken(req.headers.authorization);
    if (!caller) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }
    const { pageId, targetUid } = req.params;
    const body = (req.body || {}) as Record<string, unknown>;
    const role = typeof body.role === 'string' ? body.role.trim() : '';
    const canManageMembers = role === 'admin' && Boolean(body.canManageMembers);

    if (!isValidSegment(pageId, idPattern) || !isValidSegment(targetUid, idPattern)) {
      res.status(400).json({ error: 'Invalid page or member ID.' });
      return;
    }
    if (role !== 'admin' && role !== 'editor' && role !== 'moderator') {
      res.status(400).json({ error: 'Choose Admin, Editor, or Moderator role.' });
      return;
    }

    try {
      const [page, callerMember, targetMember, callerPub] = await Promise.all([
        fsGetDoc(`pages/${pageId}`, caller.idToken),
        fsGetDoc(`pages/${pageId}/members/${caller.uid}`, caller.idToken),
        fsGetDoc(`pages/${pageId}/members/${targetUid}`, caller.idToken),
        fsGetDoc(`users_public/${caller.uid}`, caller.idToken),
      ]);
      if (!page || !targetMember || targetMember.status !== 'active') {
        res.status(404).json({ error: 'Active page member not found.' });
        return;
      }
      const resolved = resolveServerPageRole(page, callerMember, caller.uid);
      if (!resolved.role || (resolved.role !== 'owner' && !(resolved.role === 'admin' && resolved.canManageMembers))) {
        res.status(403).json({ error: 'Only the Page Owner or authorized Admins can change member roles.' });
        return;
      }
      if (targetUid === resolved.originalOwnerId || targetMember.role === 'owner') {
        res.status(403).json({ error: 'The Original Owner cannot be demoted or removed.' });
        return;
      }

      const actorName = String(callerPub?.displayName || 'Page Admin').slice(0, 60);
      const actorPhoto = String(callerPub?.photoURL || '');
      const targetName = String(targetMember.displayName || 'Member').slice(0, 60);
      const previousRole = String(targetMember.role || 'editor');
      const logId = `log_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
      const pNotifId = `pnotif_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;

      await fsCommit(
        [
          {
            update: {
              name: fsDocPath(`pages/${pageId}/members/${targetUid}`),
              fields: {
                role: encodeFsValue(role),
                canManageMembers: encodeFsValue(canManageMembers),
              },
            },
            updateMask: { fieldPaths: ['role', 'canManageMembers', 'updatedAt'] },
            updateTransforms: [{ fieldPath: 'updatedAt', setToServerValue: 'REQUEST_TIME' }],
          },
          {
            update: {
              name: fsDocPath(`pages/${pageId}/audit_logs/${logId}`),
              fields: {
                pageId: encodeFsValue(pageId),
                action: encodeFsValue('role_changed'),
                actorId: encodeFsValue(caller.uid),
                actorName: encodeFsValue(actorName),
                actorRole: encodeFsValue(resolved.role),
                targetUserId: encodeFsValue(targetUid),
                targetUserName: encodeFsValue(targetName),
                previousRole: encodeFsValue(previousRole),
                newRole: encodeFsValue(role),
                details: encodeFsValue(`${actorName} changed ${targetName} from ${previousRole} to ${role}.`),
              },
            },
            updateTransforms: [{ fieldPath: 'createdAt', setToServerValue: 'REQUEST_TIME' }],
          },
          {
            update: {
              name: fsDocPath(`pages/${pageId}/notifications/${pNotifId}`),
              fields: {
                pageId: encodeFsValue(pageId),
                actorId: encodeFsValue(caller.uid),
                actorName: encodeFsValue(actorName),
                actorPhotoURL: encodeFsValue(actorPhoto),
                type: encodeFsValue('access_update'),
                targetId: encodeFsValue(targetUid),
                message: encodeFsValue(`${actorName} updated ${targetName}'s role to ${role}.`),
                read: encodeFsValue(false),
              },
            },
            updateTransforms: [{ fieldPath: 'createdAt', setToServerValue: 'REQUEST_TIME' }],
          },
        ],
        caller.idToken
      );
      res.json({ ok: true });
    } catch (err) {
      const code = (err as { statusCode?: number }).statusCode || 500;
      console.error('[ASN PageServer] update member failed:', err);
      res.status(code === 403 ? 403 : 400).json({
        error: err instanceof Error ? err.message : 'Unable to update member role.',
      });
    }
  });

  // Immediately revoke Page Access for a non-owner member
  router.delete('/:pageId/members/:targetUid', async (req, res) => {
    const caller = await verifyFirebaseBearerToken(req.headers.authorization);
    if (!caller) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }
    const { pageId, targetUid } = req.params;
    if (!isValidSegment(pageId, idPattern) || !isValidSegment(targetUid, idPattern)) {
      res.status(400).json({ error: 'Invalid page or member ID.' });
      return;
    }

    try {
      const [page, callerMember, targetMember, callerPub] = await Promise.all([
        fsGetDoc(`pages/${pageId}`, caller.idToken),
        fsGetDoc(`pages/${pageId}/members/${caller.uid}`, caller.idToken),
        fsGetDoc(`pages/${pageId}/members/${targetUid}`, caller.idToken),
        fsGetDoc(`users_public/${caller.uid}`, caller.idToken),
      ]);
      if (!page) {
        res.status(404).json({ error: 'Page not found.' });
        return;
      }
      const resolved = resolveServerPageRole(page, callerMember, caller.uid);
      if (targetUid === resolved.originalOwnerId || targetMember?.role === 'owner') {
        res.status(403).json({ error: 'The Original Owner cannot be removed from the page.' });
        return;
      }
      const isSelfLeave = caller.uid === targetUid;
      if (!isSelfLeave && (!resolved.role || (resolved.role !== 'owner' && !(resolved.role === 'admin' && resolved.canManageMembers)))) {
        res.status(403).json({ error: 'You do not have permission to remove this member.' });
        return;
      }

      const actorName = String(callerPub?.displayName || 'Page Admin').slice(0, 60);
      const actorPhoto = String(callerPub?.photoURL || '');
      const targetName = String(targetMember?.displayName || 'Member').slice(0, 60);
      const previousRole = String(targetMember?.role || 'manager');
      const logId = `log_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
      const pNotifId = `pnotif_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;

      const writes: FsCommitWrite[] = [
        {
          update: {
            name: fsDocPath(`pages/${pageId}/audit_logs/${logId}`),
            fields: {
              pageId: encodeFsValue(pageId),
              action: encodeFsValue('member_removed'),
              actorId: encodeFsValue(caller.uid),
              actorName: encodeFsValue(actorName),
              actorRole: encodeFsValue(resolved.role || 'editor'),
              targetUserId: encodeFsValue(targetUid),
              targetUserName: encodeFsValue(targetName),
              previousRole: encodeFsValue(previousRole),
              newRole: encodeFsValue('removed'),
              details: encodeFsValue(`${actorName} removed ${targetName}'s Page Access.`),
            },
          },
          updateTransforms: [{ fieldPath: 'createdAt', setToServerValue: 'REQUEST_TIME' }],
        },
        {
          update: {
            name: fsDocPath(`pages/${pageId}/notifications/${pNotifId}`),
            fields: {
              pageId: encodeFsValue(pageId),
              actorId: encodeFsValue(caller.uid),
              actorName: encodeFsValue(actorName),
              actorPhotoURL: encodeFsValue(actorPhoto),
              type: encodeFsValue('access_update'),
              targetId: encodeFsValue(targetUid),
              message: encodeFsValue(`${actorName} removed ${targetName} from Page Access.`),
              read: encodeFsValue(false),
            },
          },
          updateTransforms: [{ fieldPath: 'createdAt', setToServerValue: 'REQUEST_TIME' }],
        },
      ];

      if (targetMember) {
        writes.unshift({ delete: fsDocPath(`pages/${pageId}/members/${targetUid}`) });
      }

      // Sync legacy managerIds if target was in legacy array
      const legacyIds = Array.isArray(page.managerIds) ? page.managerIds.map(String) : [];
      if (legacyIds.includes(targetUid)) {
        const nextIds = legacyIds.filter((id) => id !== targetUid);
        const nextProfiles =
          page.managerProfiles && typeof page.managerProfiles === 'object'
            ? { ...(page.managerProfiles as Record<string, unknown>) }
            : {};
        delete nextProfiles[targetUid];
        writes.push({
          update: {
            name: fsDocPath(`pages/${pageId}`),
            fields: {
              managerIds: encodeFsValue(nextIds),
              managerProfiles: encodeFsValue(nextProfiles),
            },
          },
          updateMask: { fieldPaths: ['managerIds', 'managerProfiles', 'updatedAt'] },
          updateTransforms: [{ fieldPath: 'updatedAt', setToServerValue: 'REQUEST_TIME' }],
        });
      }

      await fsCommit(writes, caller.idToken);
      res.json({ ok: true });
    } catch (err) {
      const code = (err as { statusCode?: number }).statusCode || 500;
      console.error('[ASN PageServer] remove member failed:', err);
      res.status(code === 403 ? 403 : 400).json({
        error: err instanceof Error ? err.message : 'Unable to remove page member.',
      });
    }
  });

  return router;
}

export async function startServer(): Promise<http.Server> {
  const app = express();
  app.disable('x-powered-by');

  const mediaRouter = await createMediaRouter();
  app.use('/api/media', mediaRouter);
  app.use('/api/auth', createAuthVerificationRouter());
  app.use('/api/pages', createPageAccessRouter());

  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir, { index: false }));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(distDir, 'index.html'));
    });
  }

  return await new Promise<http.Server>((resolve) => {
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`ASN Social Network server running on http://localhost:${PORT}`);
      resolve(server);
    });
  });
}

const isDirectEntry =
  Boolean(process.argv[1]) &&
  path.resolve(process.argv[1]) === path.resolve(__filename);

if (isDirectEntry) {
  void startServer().catch((err) => {
    console.error('Failed to start ASN Social Network server:', err);
    process.exit(1);
  });
}
