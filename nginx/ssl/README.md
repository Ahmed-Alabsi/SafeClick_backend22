# Nginx TLS/SSL Certificates Directory

This directory contains TLS/SSL certificates mounted by `docker-compose.yml` into `/etc/nginx/ssl:ro`.

## Files:
- `fullchain.pem`: Server certificate + intermediate CA chain.
- `privkey.pem`: RSA/ECDSA private key.

## Development & Local Testing:
A self-signed 2048-bit RSA certificate has been pre-generated for `localhost` and `127.0.0.1` so the container stack boots cleanly out of the box.

## Production Setup (Let's Encrypt / Certbot / Corporate CA):
To use valid public certificates in production:
1. Obtain certificates using Certbot:
   ```bash
   certbot certonly --webroot -w /var/www/certbot -d yourdomain.com
   ```
2. Copy or symlink the certificates:
   - `fullchain.pem` -> `/etc/letsencrypt/live/yourdomain.com/fullchain.pem`
   - `privkey.pem` -> `/etc/letsencrypt/live/yourdomain.com/privkey.pem`
3. Reload Nginx:
   ```bash
   docker compose exec nginx nginx -s reload
   ```
