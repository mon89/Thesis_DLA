import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import session from 'express-session';
import cors from 'cors';
import path from 'path';
import { connectDb } from './utils/db';
import { DeviceProfile } from './models/DeviceProfile';
import apiRouter from './routes/api';
import webauthnRouter from './routes/webauthn';
import deviceRouter from './routes/device';
import evalRouter from './routes/eval';

// ── Environment ───────────────────────────────────────────────────────────────
const PORT           = parseInt(process.env.PORT ?? '3000', 10);
const ORIGIN         = process.env.ORIGIN         ?? '';
const RP_ID          = process.env.RP_ID          ?? '';
const SESSION_SECRET = process.env.SESSION_SECRET ?? 'change-me';

if (!RP_ID)          throw new Error('RP_ID is not defined');
if (!ORIGIN)         throw new Error('ORIGIN is not defined');
if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI is not defined');

const isHttps = ORIGIN.startsWith('https');

// ── App ───────────────────────────────────────────────────────────────────────
const app = express();

// Trust nginx reverse proxy (required for secure cookies over HTTPS)
app.set('trust proxy', 1);

// JSON body parsing
app.use(express.json({ limit: '1mb' }));

// CORS — allow credentials from the iOS/web client origin
app.use(cors({
  origin:      ORIGIN,
  credentials: true,
}));

// Session — cookie-based, 30 min, secure in production
app.use(session({
  secret:            SESSION_SECRET,
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure:   isHttps,
    sameSite: 'none',
    maxAge:   30 * 60 * 1000,
  },
}));

// ── Request logger ────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const ms      = Date.now() - start;
    const status  = res.statusCode;
    const icon    = status >= 500 ? '✗' : status >= 400 ? '!' : '✓';
    const s    = req.session as unknown as Record<string, unknown> | undefined;
    const auth = s?.['authenticated']   ? 'auth'   :
                 s?.['passkeyVerified'] ? 'pk-ok'  : 'anon';
    const url    = req.originalUrl.split('?')[0] ?? req.originalUrl;
    const prefix = url.startsWith('/webauthn')    ? '[passkey]' :
                   url.startsWith('/api/device')  ? '[device] ' :
                   url.startsWith('/api/eval')    ? '[eval]   ' :
                   url.startsWith('/api')         ? '[api]    ' : '[static] ';
    console.log(`[${icon}] ${prefix} ${req.method} ${url} ${status} ${ms}ms [${auth}] ip=${req.ip}`);
  });
  next();
});

// ── Static: /.well-known served with Content-Type: application/json ───────────
const wellKnownDir = path.join(__dirname, 'public', '.well-known');
app.use('/.well-known', express.static(wellKnownDir, {
  setHeaders(res) {
    res.setHeader('Content-Type', 'application/json');
  },
}));

// ── Routes ────────────────────────────────────────────────────────────────────
app.use('/api',        apiRouter);
app.use('/api/device', deviceRouter);
app.use('/api/eval',   evalRouter);
app.use('/webauthn',   webauthnRouter);

// ── Start ─────────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  await connectDb();
  await DeviceProfile.syncIndexes();
  console.log('[db] DeviceProfile indexes synced');

  app.listen(PORT, () => {
    const line = '─'.repeat(42);
    console.log(`┌${line}┐`);
    console.log(`│  DLA Authentication Server               │`);
    console.log(`│  RP_ID  : ${RP_ID.padEnd(31)}│`);
    console.log(`│  Origin : ${ORIGIN.padEnd(31)}│`);
    console.log(`│  Port   : ${String(PORT).padEnd(31)}│`);
    console.log(`└${line}┘`);
  });
}

main().catch(err => {
  console.error('[fatal]', err);
  process.exit(1);
});
