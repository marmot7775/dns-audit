"""
Doc 88: no log the site writes carries the visitor's IP address.

The privacy page says the application writes the IP to no file and that
the web server's access log leaves out the IP and user agent. Three things
could quietly break that: the nginx access log in its default format,
uvicorn's own access log (stdout, which journald and syslog keep), and the
app's INFO lines. The nginx error log does carry "client: <ip>", and the
page says so.
"""
import os
import re

REPO = os.path.join(os.path.dirname(__file__), "..")


def _read(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as f:
        return f.read()


def test_nginx_log_format_leaves_out_ip_and_user_agent():
    conf = _read("deploy/nginx.conf")
    fmt = re.search(r"log_format\s+noip\s+'([^']*)';", conf)
    assert fmt, "deploy/nginx.conf defines no noip log_format"
    for var in ("$remote_addr", "$http_user_agent", "$http_x_forwarded_for",
                "$http_cf_connecting_ip", "$realip_remote_addr", "$http_referer"):
        assert var not in fmt.group(1), var
    for var in ("$time_local", "$request_method", "$uri", "$status",
                "$body_bytes_sent", "$request_time"):
        assert var in fmt.group(1), var


def test_every_access_log_uses_the_format_or_is_off():
    conf = _read("deploy/nginx.conf")
    lines = re.findall(r"^\s*access_log\s+([^;]+);", conf, re.MULTILINE)
    assert lines
    for value in lines:
        assert value.strip() == "off" or value.split()[-1] == "noip", value
    # Each server block sets its own, so nginx.conf's http-level default
    # (combined format, IP first) never applies.
    for block in conf.split("\nserver {")[1:]:
        head = block.split("location")[0]
        assert "access_log /var/log/nginx/access.log noip;" in head


def test_uvicorn_access_log_is_off():
    unit = _read("deploy/dns-auditor.service")
    execstart = re.search(r"^ExecStart=(.*)$", unit, re.MULTILINE).group(1)
    assert "--no-access-log" in execstart.split()


def test_no_app_log_line_carries_the_client_ip():
    src = _read("server.py")
    calls = re.findall(r"\blog\.\w+\((.*)\)", src)
    for call in calls:
        assert "ip=" not in call, call
        assert "client_ip" not in call, call
