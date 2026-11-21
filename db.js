'use strict';
const { Pool } = require('pg');

const url = process.env.DATABASE_URL;
if (!url) {
  console.error('DATABASE_URL is not set. Add it in Render > Environment.');
  process.exit(1);
}

// Render's internal connection string (host like "dpg-xxxx-a") needs no SSL;
// the external one (host ending in render.com) does.
const needsSsl = process.env.PGSSL === 'true' || /\.render\.com/.test(url);
const pool = new Pool({
  connectionString: url,
  ssl: needsSsl ? { rejectUnauthorized: false } : false,
  max: 5,
});

const STATUSES = ['new', 'quoted', 'approved', 'in_production', 'ready', 'delivered', 'cancelled'];

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id              SERIAL PRIMARY KEY,
      created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
      source          TEXT NOT NULL DEFAULT 'website',
      status          TEXT NOT NULL DEFAULT 'new',
      customer_name   TEXT NOT NULL,
      email           TEXT,
      phone           TEXT,
      organization    TEXT,
      occasion        TEXT,
      quantity        INTEGER,
      ball_color      TEXT,
      need_by         DATE,
      logo_choice     TEXT,
      design_notes    TEXT,
      design          JSONB,
      logo_image      TEXT,
      logo_filename   TEXT,
      preview_image   TEXT,
      price_cents     INTEGER,
      paid_cents      INTEGER NOT NULL DEFAULT 0,
      payment_method  TEXT,
      internal_notes  TEXT
    );
    CREATE TABLE IF NOT EXISTS order_events (
      id        SERIAL PRIMARY KEY,
      order_id  INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
      at        TIMESTAMPTZ NOT NULL DEFAULT now(),
      kind      TEXT NOT NULL,
      text      TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS orders_status_idx ON orders(status);
    CREATE INDEX IF NOT EXISTS orders_created_idx ON orders(created_at DESC);
    CREATE INDEX IF NOT EXISTS order_events_order_idx ON order_events(order_id, at);
  `);
}

module.exports = { pool, migrate, STATUSES };
