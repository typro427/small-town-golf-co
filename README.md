# Small Town Golf Co.

The website, online ordering, and the sales portal at /admin.

## What's here
- `public/` — the website (index.html, images)
- `admin/index.html` — the sales portal (sign in at https://smalltowngolfco.com/admin)
- `server.js` — saves website orders and runs the sales portal
- `db.js` — sets up the order database automatically on first start
- `package.json` — the packages the server needs

## Settings on Render (Environment tab)
| Setting | What it is |
| --- | --- |
| DATABASE_URL | Your Render database's internal connection string |
| ADMIN_PASSWORD | The sales portal password (10+ characters). Change it any time; it takes effect on the next deploy. |
| SESSION_SECRET | A long random string that keeps sign-ins secure. Changing it signs everyone out. |
| SITE_URL | https://smalltowngolfco.com (used in order notification emails) |

### Optional: get an email for every new order
1. Turn on 2-Step Verification for SmallTownGolfCo@gmail.com, then create an App Password (Google Account > Security > App passwords).
2. Add these settings on Render: `SMTP_USER` = SmallTownGolfCo@gmail.com, `SMTP_PASS` = the 16-letter app password.
