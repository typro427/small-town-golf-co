# Small Town Golf Co. website

A one-page static site: custom golf balls, a ball editor with image upload, and an order request form.
There is no build step and no server code — Render just serves these files.

## Files
- `index.html` — the whole website (styles, scripts and images are built in)
- `og-image.jpg` — the picture that shows when the link is shared on Facebook, texts, etc.
- `favicon.png`, `apple-touch-icon.png` — browser tab and phone home-screen icons
- `robots.txt`, `sitemap.xml` — help Google find the site
- `render.yaml` — tells Render how to host it

## Before you go live, check these in index.html
- Order email: search for `orders@smalltowngolfco.com` and replace it everywhere with your real address.
- Domain: `smalltowngolfco.com` is used in the share tags, robots.txt and sitemap.xml. Change it if your domain is different.
