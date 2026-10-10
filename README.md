# Travel Checklist — travel.dev-quik.com

A personal travel packing checklist web app. Mobile-first, single static frontend
backed by Postgres + PostgREST on Jonathan's Contabo VPS.

## Stack

- **Frontend:** static `index.html` + `styles.css` + `app.js` served by nginx from `/var/www/travel`
- **API:** PostgREST (`postgrest-travel.service`) on `127.0.0.1:3001`, proxied by nginx at `/api/`
- **Database:** Postgres `travel` database on the VPS
- **Auth:** same pattern as the NFL pick'em site — `users` table with bcrypt
  password hashes (pgcrypto), `sessions` table with uuid tokens, all access
  through `SECURITY DEFINER` RPCs. The `anon` role can only `EXECUTE` the RPCs.

## Files

- `index.html` — auth view, trips list, trip detail, trip modal
- `styles.css` — mobile-first styles
- `app.js` — SPA logic, session in `localStorage`
- `schema.sql` — full database schema: tables, auth RPCs (`travel_register`,
  `travel_login`, `travel_me`, `travel_logout`), trip RPCs, checklist-item RPCs,
  `travel_seed_starter` (36-item starter packing list), and the anon lockdown

## Deploy

```bash
# database
sudo -u postgres psql -c "CREATE DATABASE travel;"
sudo -u postgres psql -d travel -v ON_ERROR_STOP=1 -f schema.sql

# postgrest: /opt/postgrest/travel.conf (port 3001) + postgrest-travel.service

# site files
tar xzf travel-site.tar.gz -C /var/www/travel && chmod -R a+rX /var/www/travel

# nginx: sites-available/travel-dev-quik (see VPS), certbot for travel.dev-quik.com
```

Auth RPCs are rate-limited in nginx (`travel_auth` zone, 10r/m) like the candy
login endpoint.
