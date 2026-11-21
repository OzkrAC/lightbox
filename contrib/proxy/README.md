# A proxy for `--net proxy`

A container created with `--net proxy:<port>` reaches one place: that TCP
port of lightbox's gateway, the bridge's address. Everything else is
refused by lightbox's firewall rules, name servers included, and its
`resolv.conf` names none. `exec` and the init hook have `HTTP_PROXY`,
`HTTPS_PROXY` and `NO_PROXY` in both spellings. curl, wget, pip, npm and git
read them.

lightbox ships no proxy. Which names a container may reach, and whatever a
proxy adds to a request, is the proxy's configuration. This directory has
one for Squid 6 with a list of allowed names. The lifecycle suite runs it as
it is, but for the listening address, the subnet and the path of the list
(`t_proxy_example` in `tests/lifecycle.sh`).

## Use

    apt-get install squid
    cp squid.conf /etc/squid/squid.conf
    cp lightbox-allowed-domains /etc/squid/lightbox-allowed-domains
    systemctl restart squid
    lightbox create agent --net proxy:3128

- `squid.conf` is written for lightbox.conf's defaults, `subnet = 10.0.0.0/24`
  and `gw = 10.0.0.1`. With others, change `http_port` and `acl lightbox`.
  It replaces the distribution's `squid.conf`, whose `http_port 3128` listens
  on every interface.
- `lightbox-allowed-domains` has one name a line. `example.com` is that name
  alone, `.example.com` it and every name under it. Squid reads it when it
  starts and on `squid -k reconfigure`.
- Squid listens on the bridge's address, which is there once `lightbox setup`,
  or the first start after a boot, has made the bridge. Start Squid after
  that, or let it listen before with `sysctl -w net.ipv4.ip_nonlocal_bind=1`.
- A host firewall that drops what reaches the host has to let the port in
  from the bridge, such as `ufw allow in on br0 to 10.0.0.1 port 3128 proto tcp`.

## What it does

- **Names on the list only.** A request for another name is refused before
  anything is looked up, so a name cannot carry data out by DNS. A request
  for an address is refused: `-n` keeps Squid from looking it up to a name.
- **No name leads inward.** A name on the list that resolves to the host, its
  networks, another container, a metadata service or any range that is no
  one's on the internet is refused, as `--net outside` refuses those.
- **Ports 443 and 80 only.** HTTPS goes through `CONNECT` to port 443, plain
  HTTP to port 80.
- **Nothing about the container goes out, and nothing is cached.** No
  `X-Forwarded-For` or `Via`, and no response kept for another container.
- **A record.** `/var/log/squid/access.log` has every request, allowed or not.

## What it does not do

- It adds no credentials and does not look inside HTTPS. A proxy that adds a
  token to a request has to end the TLS connection itself, with a CA that the
  container trusts, such as Squid's SSL bump. That is a configuration of its
  own, with its own risks, and is not here.
- The variables only tell programs where the proxy is. A program that ignores
  them reaches nothing, as the rules refuse everything but the proxy's port.
