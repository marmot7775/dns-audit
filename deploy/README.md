# deploy

- `dns-auditor.service`: template of the systemd unit. The live copy is `/etc/systemd/system/dns-auditor.service` on the droplet.
- `nginx.conf`: copy of the droplet's nginx site config, with the user replaced by DEPLOY_USER. The live file is `/etc/nginx/sites-enabled/dns-audit`; change it there, run `sudo nginx -t`, reload nginx, then update this copy.
- `no-dns-default-route.conf`: systemd-networkd drop-in that keeps the private interface out of DNS routing. On a droplet with a private network interface, install it and reload:

  ```bash
  sudo mkdir -p /etc/systemd/network/10-netplan-eth1.network.d
  sudo cp deploy/no-dns-default-route.conf /etc/systemd/network/10-netplan-eth1.network.d/
  sudo networkctl reload
  ```

  Then confirm NXDOMAIN comes back through the stub in milliseconds, not after a timeout: `dig +time=5 +tries=1 zz-probe.mozilla.org TXT` shows `status: NXDOMAIN`, `SERVER: 127.0.0.53` and a query time of a few ms. Without it, every NXDOMAIN through 127.0.0.53 timed out on 2026-10-12 while positive answers kept working (Doc 100).
