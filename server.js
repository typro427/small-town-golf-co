'use strict';
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { pool, migrate, STATUSES } = require('./db');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const IS_PROD = process.env.NODE_ENV === 'production' || !!process.env.RENDER;
const SESSION_HOURS = 12;

if (ADMIN_PASSWORD.length < 10 || SESSION_SECRET.length < 32) {
  console.error('Set ADMIN_PASSWORD (10+ characters) and SESSION_SECRET (32+ characters) in Render > Environment.');
  process.exit(1);
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

// ---------- security headers ----------
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.set('X-Frame-Options', 'DENY');
  if (IS_PROD) res.set('Strict-Transport-Security', 'max-age=31536000');
  next();
});

// ---------- tiny in-memory rate limiter ----------
function limiter({ windowMs, max, message }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset < now) hits.delete(k);
  }, windowMs).unref();
  return (req, res, next) => {
    const now = Date.now();
    const key = req.ip;
    let h = hits.get(key);
    if (!h || h.reset < now) { h = { n: 0, reset: now + windowMs }; hits.set(key, h); }
    h.n += 1;
    if (h.n > max) return res.status(429).json({ error: message });
    next();
  };
}

// ---------- helpers ----------
// Express 4 does not catch errors thrown in async handlers; route them to the error handler.
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const clean = (v, max = 500) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const intOrNull = (v) => {
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? n : null;
};
const moneyToCents = (v) => {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(String(v).replace(/[$,\s]/g, ''));
  return Number.isFinite(n) && n >= 0 && n < 10_000_000 ? Math.round(n * 100) : undefined;
};
const dateOrNull = (v) => (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : null);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const IMG_RE = /^data:image\/(png|jpeg|webp|gif|svg\+xml);base64,[A-Za-z0-9+/=]+$/;
const orderNo = (id) => `STG-${1000 + id}`;

function validImage(dataUrl, maxBytes) {
  if (!dataUrl) return null;
  if (typeof dataUrl !== 'string' || !IMG_RE.test(dataUrl)) return undefined;
  const b64 = dataUrl.slice(dataUrl.indexOf(',') + 1);
  if (b64.length * 0.75 > maxBytes) return undefined;
  return dataUrl;
}

async function logEvent(client, orderId, kind, text) {
  await client.query('INSERT INTO order_events (order_id, kind, text) VALUES ($1, $2, $3)', [orderId, kind, text]);
}

// ---------- optional email notification ----------
let mailer = null;
if (process.env.SMTP_USER && process.env.SMTP_PASS) {
  const nodemailer = require('nodemailer');
  mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: Number(process.env.SMTP_PORT || 465),
    secure: Number(process.env.SMTP_PORT || 465) === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
}
async function notifyNewOrder(o) {
  if (!mailer) return;
  const to = process.env.NOTIFY_EMAIL || process.env.SMTP_USER;
  const site = process.env.SITE_URL || '';
  const lines = [
    `New order ${orderNo(o.id)} from ${o.customer_name}`,
    '',
    `Email: ${o.email || '-'}`,
    `Phone: ${o.phone || '-'}`,
    `Team / business / event: ${o.organization || '-'}`,
    `For: ${o.occasion || '-'}`,
    `Quantity: ${o.quantity ?? '-'}`,
    `Ball color: ${o.ball_color || '-'}`,
    `Need by: ${o.need_by || 'Flexible'}`,
    `Logo: ${o.logo_choice || '-'}${o.logo_filename ? ` (${o.logo_filename} uploaded)` : ''}`,
    '',
    'Design details:',
    o.design_notes || '(none)',
    '',
    site ? `Open it in your sales portal: ${site}/admin#order-${o.id}` : 'Open your sales portal at /admin',
  ];
  try {
    await mailer.sendMail({
      from: `"Small Town Golf Co. website" <${process.env.SMTP_USER}>`,
      to,
      replyTo: o.email || undefined,
      subject: `New order ${orderNo(o.id)} — ${o.organization || o.customer_name} (${o.quantity ?? '?'} balls)`,
      text: lines.join('\n'),
    });
  } catch (err) {
    console.error('Order notification email failed:', err.message);
  }
}

// ---------- admin session (signed cookie) ----------
const COOKIE = 'stg_admin';
function sign(value) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url');
}
function makeToken() {
  const exp = Date.now() + SESSION_HOURS * 3600 * 1000;
  const payload = `admin.${exp}`;
  return `${payload}.${sign(payload)}`;
}
function readCookie(req, name) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > -1 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}
function isAuthed(req) {
  const tok = readCookie(req, COOKIE);
  if (!tok) return false;
  const parts = tok.split('.');
  if (parts.length !== 3) return false;
  const payload = `${parts[0]}.${parts[1]}`;
  const expected = sign(payload);
  const a = Buffer.from(parts[2]);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  return Number(parts[1]) > Date.now();
}
function setSession(res, token, maxAgeSec) {
  const attrs = [`${COOKIE}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${maxAgeSec}`];
  if (IS_PROD) attrs.push('Secure');
  res.set('Set-Cookie', attrs.join('; '));
}
function requireAdmin(req, res, next) {
  if (!isAuthed(req)) return res.status(401).json({ error: 'Please sign in again.' });
  // Every admin write must come from our own page (SameSite cookie + custom header).
  if (req.method !== 'GET' && req.get('X-Requested-With') !== 'stg-admin') {
    return res.status(403).json({ error: 'Request blocked.' });
  }
  res.set('Cache-Control', 'no-store');
  next();
}
function passwordMatches(input) {
  const a = crypto.createHash('sha256').update(String(input)).digest();
  const b = crypto.createHash('sha256').update(ADMIN_PASSWORD).digest();
  return crypto.timingSafeEqual(a, b);
}

// ---------- public: place an order ----------
app.post(
  '/api/orders',
  limiter({ windowMs: 60 * 60 * 1000, max: 20, message: 'Too many orders from this connection. Please email us instead.' }),
  express.json({ limit: '9mb' }),
  wrap(async (req, res) => {
    const b = req.body || {};
    if (clean(b.company_website)) return res.json({ ok: true, orderNo: 'STG-0000' }); // honeypot: bots fill hidden field

    const name = clean(b.name, 120);
    const email = clean(b.email, 200);
    const quantity = intOrNull(b.quantity);
    const problems = [];
    if (!name) problems.push('your name');
    if (!EMAIL_RE.test(email)) problems.push('a valid email');
    if (!(quantity > 0 && quantity <= 100000)) problems.push('how many balls');
    const logo = validImage(b.logoImage, 6 * 1024 * 1024);
    const preview = validImage(b.previewImage, 2 * 1024 * 1024);
    if (logo === undefined) problems.push('a logo image under 6 MB (PNG, JPG, SVG or WebP)');
    if (preview === undefined) problems.push('a smaller preview image');
    if (problems.length) return res.status(400).json({ error: `Please add ${problems.join(', ')}.` });

    let design = null;
    if (b.design && typeof b.design === 'object') {
      const s = JSON.stringify(b.design);
      if (s.length < 4000) design = b.design;
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        `INSERT INTO orders (source, customer_name, email, phone, organization, occasion, quantity, ball_color,
           need_by, logo_choice, design_notes, design, logo_image, logo_filename, preview_image)
         VALUES ('website',$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
         RETURNING *`,
        [name, email, clean(b.phone, 40), clean(b.organization, 200), clean(b.occasion, 80), quantity,
          clean(b.ballColor, 60), dateOrNull(b.needBy), clean(b.logoChoice, 80), clean(b.notes, 4000), design,
          logo, logo ? clean(b.logoFilename, 200) : null, preview]
      );
      await logEvent(client, rows[0].id, 'created', 'Order placed on the website');
      await client.query('COMMIT');
      res.status(201).json({ ok: true, orderNo: orderNo(rows[0].id) });
      notifyNewOrder(rows[0]);
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      console.error('Order save failed:', err);
      res.status(500).json({ error: 'We could not save your order. Please email us instead.' });
    } finally {
      client.release();
    }
  })
);

// ---------- admin auth ----------
const adminJson = express.json({ limit: '9mb' });
app.post(
  '/api/admin/login',
  limiter({ windowMs: 15 * 60 * 1000, max: 10, message: 'Too many sign-in attempts. Try again in 15 minutes.' }),
  express.json({ limit: '10kb' }),
  (req, res) => {
    if (!passwordMatches((req.body || {}).password || '')) {
      return res.status(401).json({ error: 'That password is not right.' });
    }
    setSession(res, makeToken(), SESSION_HOURS * 3600);
    res.json({ ok: true });
  }
);
app.post('/api/admin/logout', (req, res) => {
  setSession(res, '', 0);
  res.json({ ok: true });
});
app.get('/api/admin/me', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ authed: isAuthed(req) });
});

// ---------- admin: orders ----------
const LIST_COLS = `id, created_at, updated_at, source, status, customer_name, email, phone, organization, occasion,
  quantity, ball_color, need_by, logo_choice, price_cents, paid_cents, payment_method,
  (logo_image IS NOT NULL) AS has_logo, (preview_image IS NOT NULL) AS has_preview`;

function shapeOrder(r) {
  return { ...r, order_no: orderNo(r.id), need_by: r.need_by ? toISODate(r.need_by) : null };
}
function toISODate(d) {
  if (typeof d === 'string') return d.slice(0, 10);
  const y = d.getFullYear(), m = String(d.getMonth() + 1).padStart(2, '0'), day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}
// Return DATE columns as plain strings so time zones never shift them.
require('pg').types.setTypeParser(1082, (v) => v);

app.get('/api/admin/orders', requireAdmin, wrap(async (req, res) => {
  const where = [];
  const args = [];
  const status = clean(req.query.status, 40);
  if (status && status !== 'all') {
    if (status === 'open') where.push(`status NOT IN ('delivered','cancelled')`);
    else if (STATUSES.includes(status)) { args.push(status); where.push(`status = $${args.length}`); }
  }
  const q = clean(req.query.q, 100);
  if (q) {
    args.push(`%${q}%`);
    const p = `$${args.length}`;
    const num = q.replace(/^stg-?/i, '');
    const idCond = /^\d+$/.test(num) ? ` OR id = ${Number(num) - 1000}` : '';
    where.push(`(customer_name ILIKE ${p} OR email ILIKE ${p} OR organization ILIKE ${p} OR phone ILIKE ${p} OR design_notes ILIKE ${p}${idCond})`);
  }
  const sql = `SELECT ${LIST_COLS} FROM orders ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY created_at DESC LIMIT 500`;
  const { rows } = await pool.query(sql, args);
  res.json({ orders: rows.map(shapeOrder) });
}));

app.get('/api/admin/stats', requireAdmin, wrap(async (req, res) => {
  const { rows: [s] } = await pool.query(`
    SELECT
      count(*) FILTER (WHERE status NOT IN ('delivered','cancelled'))                       AS open_orders,
      count(*) FILTER (WHERE status = 'new')                                                AS new_orders,
      count(*) FILTER (WHERE status NOT IN ('delivered','cancelled') AND need_by IS NOT NULL
                         AND need_by <= current_date + 7)                                   AS due_soon,
      COALESCE(sum(GREATEST(COALESCE(price_cents,0) - paid_cents, 0)) FILTER (WHERE status <> 'cancelled'), 0) AS outstanding,
      COALESCE(sum(price_cents) FILTER (WHERE status <> 'cancelled'), 0)                     AS booked_total,
      COALESCE(sum(paid_cents), 0)                                                           AS collected_total,
      COALESCE(sum(quantity) FILTER (WHERE status NOT IN ('cancelled')), 0)                  AS balls_total,
      count(*)                                                                               AS all_orders
    FROM orders`);
  const { rows: byStatus } = await pool.query(`SELECT status, count(*)::int AS n FROM orders GROUP BY status`);
  const { rows: [month] } = await pool.query(`
    SELECT COALESCE(sum(amount_cents), 0) AS collected_this_month FROM (
      SELECT (regexp_match(text, 'amount_cents=([0-9]+)'))[1]::int AS amount_cents
      FROM order_events
      WHERE kind = 'payment' AND date_trunc('month', at) = date_trunc('month', now())
    ) t`);
  const counts = Object.fromEntries(STATUSES.map((st) => [st, 0]));
  for (const r of byStatus) counts[r.status] = r.n;
  res.json({
    openOrders: Number(s.open_orders),
    newOrders: Number(s.new_orders),
    dueSoon: Number(s.due_soon),
    outstandingCents: Number(s.outstanding),
    bookedCents: Number(s.booked_total),
    collectedCents: Number(s.collected_total),
    collectedThisMonthCents: Number(month.collected_this_month),
    ballsTotal: Number(s.balls_total),
    allOrders: Number(s.all_orders),
    counts,
  });
}));

app.get('/api/admin/orders/:id', requireAdmin, wrap(async (req, res) => {
  const id = intOrNull(req.params.id);
  const { rows } = await pool.query(`SELECT ${LIST_COLS}, design_notes, design, logo_filename, internal_notes FROM orders WHERE id = $1`, [id]);
  if (!rows.length) return res.status(404).json({ error: 'That order no longer exists.' });
  const { rows: events } = await pool.query(
    `SELECT id, at, kind, regexp_replace(text, ' ?\\[amount_cents=[0-9]+\\]', '') AS text FROM order_events WHERE order_id = $1 ORDER BY at DESC, id DESC`, [id]);
  res.json({ order: shapeOrder(rows[0]), events });
}));

function sendImage(column) {
  return wrap(async (req, res) => {
    const id = intOrNull(req.params.id);
    const { rows } = await pool.query(`SELECT ${column} AS img, logo_filename FROM orders WHERE id = $1`, [id]);
    const img = rows[0] && rows[0].img;
    if (!img) return res.status(404).end();
    const m = /^data:(image\/[a-z+]+);base64,(.*)$/.exec(img);
    if (!m) return res.status(404).end();
    res.set('Content-Type', m[1]);
    res.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; sandbox");
    res.set('Cache-Control', 'private, no-store');
    if (req.query.download) {
      const ext = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp', 'image/gif': 'gif', 'image/svg+xml': 'svg' }[m[1]] || 'img';
      const base = column === 'logo_image' && rows[0].logo_filename ? rows[0].logo_filename.replace(/[^\w.-]+/g, '_') : `${orderNo(id)}-${column === 'logo_image' ? 'logo' : 'preview'}.${ext}`;
      res.set('Content-Disposition', `attachment; filename="${base}"`);
    }
    res.send(Buffer.from(m[2], 'base64'));
  });
}
app.get('/api/admin/orders/:id/logo', requireAdmin, sendImage('logo_image'));
app.get('/api/admin/orders/:id/preview', requireAdmin, sendImage('preview_image'));

const EDITABLE = {
  status: (v) => (STATUSES.includes(v) ? v : undefined),
  customer_name: (v) => clean(v, 120) || undefined,
  email: (v) => { const e = clean(v, 200); return e === '' || EMAIL_RE.test(e) ? e : undefined; },
  phone: (v) => clean(v, 40),
  organization: (v) => clean(v, 200),
  occasion: (v) => clean(v, 80),
  quantity: (v) => (v === '' || v === null ? null : (intOrNull(v) >= 0 ? intOrNull(v) : undefined)),
  ball_color: (v) => clean(v, 60),
  need_by: (v) => (v === '' || v === null ? null : dateOrNull(v) || undefined),
  logo_choice: (v) => clean(v, 80),
  design_notes: (v) => clean(v, 4000),
  price_cents: (v) => moneyToCents(v),
  payment_method: (v) => clean(v, 60),
  internal_notes: (v) => clean(v, 8000),
};
const LABELS = {
  status: 'Status', customer_name: 'Name', email: 'Email', phone: 'Phone', organization: 'Team / business',
  occasion: 'Occasion', quantity: 'Quantity', ball_color: 'Ball color', need_by: 'Need by', logo_choice: 'Logo',
  design_notes: 'Design details', price_cents: 'Price', payment_method: 'Payment method', internal_notes: 'Internal notes',
};
const STATUS_NAMES = {
  new: 'New', quoted: 'Quoted', approved: 'Approved', in_production: 'In production', ready: 'Ready',
  delivered: 'Delivered', cancelled: 'Cancelled',
};
const fmtMoney = (c) => (c === null || c === undefined ? '—' : `$${(c / 100).toFixed(2)}`);

function readEdits(body) {
  const out = {};
  const bad = [];
  for (const [k, fn] of Object.entries(EDITABLE)) {
    if (Object.prototype.hasOwnProperty.call(body, k)) {
      const v = fn(body[k]);
      if (v === undefined) bad.push(LABELS[k]);
      else out[k] = v;
    }
  }
  return { out, bad };
}

app.post('/api/admin/orders', requireAdmin, adminJson, wrap(async (req, res) => {
  const { out, bad } = readEdits(req.body || {});
  if (bad.length) return res.status(400).json({ error: `Check these fields: ${bad.join(', ')}.` });
  if (!out.customer_name) return res.status(400).json({ error: 'Add the customer’s name.' });
  const logo = validImage((req.body || {}).logoImage, 6 * 1024 * 1024);
  if (logo === undefined) return res.status(400).json({ error: 'The logo must be a PNG, JPG, SVG or WebP under 6 MB.' });
  const cols = Object.keys(out);
  const vals = Object.values(out);
  cols.push('source'); vals.push('manual');
  if (logo) { cols.push('logo_image', 'logo_filename'); vals.push(logo, clean(req.body.logoFilename, 200)); }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `INSERT INTO orders (${cols.join(',')}) VALUES (${cols.map((_, i) => `$${i + 1}`).join(',')}) RETURNING id`, vals);
    await logEvent(client, rows[0].id, 'created', 'Order added by hand in the sales portal');
    await client.query('COMMIT');
    res.status(201).json({ ok: true, id: rows[0].id, orderNo: orderNo(rows[0].id) });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(err);
    res.status(500).json({ error: 'Could not save the order. Try again.' });
  } finally { client.release(); }
}));

app.patch('/api/admin/orders/:id', requireAdmin, adminJson, wrap(async (req, res) => {
  const id = intOrNull(req.params.id);
  const body = req.body || {};
  const { out, bad } = readEdits(body);
  if (bad.length) return res.status(400).json({ error: `Check these fields: ${bad.join(', ')}.` });
  const logo = body.logoImage === null ? null : validImage(body.logoImage, 6 * 1024 * 1024);
  if (body.logoImage !== undefined && logo === undefined) return res.status(400).json({ error: 'The logo must be a PNG, JPG, SVG or WebP under 6 MB.' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: cur } = await client.query('SELECT * FROM orders WHERE id = $1 FOR UPDATE', [id]);
    if (!cur.length) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'That order no longer exists.' }); }
    const before = cur[0];
    const sets = [];
    const vals = [];
    const changes = [];
    for (const [k, v] of Object.entries(out)) {
      const old = k === 'need_by' ? (before.need_by || null) : before[k];
      if ((old ?? '') === (v ?? '')) continue;
      vals.push(v); sets.push(`${k} = $${vals.length}`);
      if (k === 'status') changes.push(`Status: ${STATUS_NAMES[before.status] || before.status} → ${STATUS_NAMES[v]}`);
      else if (k === 'price_cents') changes.push(`Price: ${fmtMoney(before.price_cents)} → ${fmtMoney(v)}`);
      else if (k === 'internal_notes' || k === 'design_notes') changes.push(`${LABELS[k]} updated`);
      else changes.push(`${LABELS[k]}: ${old || '—'} → ${v || '—'}`);
    }
    if (body.logoImage !== undefined) {
      vals.push(logo); sets.push(`logo_image = $${vals.length}`);
      vals.push(logo ? clean(body.logoFilename, 200) : null); sets.push(`logo_filename = $${vals.length}`);
      changes.push(logo ? 'Logo file replaced' : 'Logo file removed');
    }
    // Payments are recorded as additions, so the history shows each one.
    const pay = moneyToCents(body.addPaymentDollars);
    if (body.addPaymentDollars !== undefined && body.addPaymentDollars !== '') {
      if (pay === undefined || pay === null || pay === 0) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Enter the payment amount in dollars, like 45 or 45.50.' }); }
      vals.push(before.paid_cents + pay); sets.push(`paid_cents = $${vals.length}`);
      const method = clean(body.paymentMethodForPayment, 60);
      await logEvent(client, id, 'payment', `Payment recorded: ${fmtMoney(pay)}${method ? ` (${method})` : ''} [amount_cents=${pay}]`);
    }
    if (body.refundDollars !== undefined && body.refundDollars !== '') {
      const ref = moneyToCents(body.refundDollars);
      if (!ref) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Enter the refund amount in dollars.' }); }
      vals.push(Math.max(0, before.paid_cents - ref)); sets.push(`paid_cents = $${vals.length}`);
      await logEvent(client, id, 'payment', `Refund recorded: ${fmtMoney(ref)} [amount_cents=0]`);
    }
    if (sets.length) {
      vals.push(id);
      await client.query(`UPDATE orders SET ${sets.join(', ')}, updated_at = now() WHERE id = $${vals.length}`, vals);
    }
    for (const c of changes) await logEvent(client, id, c.startsWith('Status') ? 'status' : 'edit', c);
    const note = clean(body.addNote, 2000);
    if (note) await logEvent(client, id, 'note', note);
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(err);
    res.status(500).json({ error: 'Could not save the changes. Try again.' });
  } finally { client.release(); }
}));

app.delete('/api/admin/orders/:id', requireAdmin, wrap(async (req, res) => {
  const id = intOrNull(req.params.id);
  const { rowCount } = await pool.query('DELETE FROM orders WHERE id = $1', [id]);
  if (!rowCount) return res.status(404).json({ error: 'That order no longer exists.' });
  res.json({ ok: true });
}));

app.get('/api/admin/export.csv', requireAdmin, wrap(async (req, res) => {
  const { rows } = await pool.query(`SELECT ${LIST_COLS}, design_notes, internal_notes FROM orders ORDER BY created_at DESC`);
  const head = ['Order', 'Placed', 'Source', 'Status', 'Customer', 'Email', 'Phone', 'Team / business', 'Occasion', 'Quantity',
    'Ball color', 'Need by', 'Logo', 'Price', 'Paid', 'Balance', 'Payment method', 'Design details', 'Internal notes'];
  const esc = (v) => {
    let s = v === null || v === undefined ? '' : String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`; // stop spreadsheet formula injection
    return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const money = (c) => (c === null || c === undefined ? '' : (c / 100).toFixed(2));
  const lines = [head.join(',')];
  for (const r of rows) {
    lines.push([
      orderNo(r.id), new Date(r.created_at).toISOString().slice(0, 10), r.source, STATUS_NAMES[r.status] || r.status,
      r.customer_name, r.email, r.phone, r.organization, r.occasion, r.quantity, r.ball_color, r.need_by || '',
      r.logo_choice, money(r.price_cents), money(r.paid_cents),
      r.price_cents === null ? '' : money(Math.max(0, r.price_cents - r.paid_cents)),
      r.payment_method, r.design_notes, r.internal_notes,
    ].map(esc).join(','));
  }
  res.set('Content-Type', 'text/csv; charset=utf-8');
  res.set('Content-Disposition', `attachment; filename="small-town-golf-orders-${new Date().toISOString().slice(0, 10)}.csv"`);
  res.send('﻿' + lines.join('\r\n'));
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

// ---------- pages ----------
app.get(['/admin', '/admin/'], (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.sendFile(path.join(__dirname, 'admin.html'));
});
app.get('/healthz', async (req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true }); } catch { res.status(503).json({ ok: false }); }
});
// Only these files are public. Everything else in the project (server code, settings) is never served.
const PUBLIC_FILES = new Set(['index.html', 'og-image.jpg', 'favicon.png', 'apple-touch-icon.png', 'robots.txt', 'sitemap.xml']);
app.get('/', (req, res) => { res.set('Cache-Control', 'no-cache'); res.sendFile(path.join(__dirname, 'index.html')); });
app.get('/:file', (req, res, next) => {
  const f = req.params.file;
  if (!PUBLIC_FILES.has(f)) return next();
  res.set('Cache-Control', /\.(png|jpg)$/.test(f) ? 'public, max-age=604800' : 'no-cache');
  res.sendFile(path.join(__dirname, f));
});
app.use((req, res) => res.status(404).sendFile(path.join(__dirname, 'index.html')));

// JSON errors (bad JSON, too large) instead of HTML stack traces.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'That upload is too large. Try a smaller image.' });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Something went wrong sending the form. Try again.' });
  console.error(err);
  res.status(500).json({ error: 'Something went wrong. Try again.' });
});

migrate()
  .then(() => app.listen(PORT, () => console.log(`Small Town Golf Co. running on port ${PORT}`)))
  .catch((err) => { console.error('Database setup failed:', err); process.exit(1); });
