# deploy

- `dns-auditor.service`: template of the systemd unit. The live copy is `/etc/systemd/system/dns-auditor.service` on the droplet.
- `nginx.conf`: copy of the droplet's nginx site config, with the user replaced by DEPLOY_USER. The live file is `/etc/nginx/sites-enabled/dns-audit`; change it there, run `sudo nginx -t`, reload nginx, then update this copy.
