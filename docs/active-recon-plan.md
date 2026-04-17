# Active Recon Design Notes

This document reflects the implemented active-recon behavior.

## Implemented Components

- `resolver` service:
  - image: `klutchell/unbound:1.19.3`
  - command: `unbound -d -c /etc/unbound/unbound.conf`
  - mount: `./config/unbound/unbound.conf:/etc/unbound/unbound.conf:ro`
  - mount: `/opt/recon-platform/config/unbound/root.hints:/etc/unbound/named.cache:ro`
- `worker-dns-brute` service:
  - uses `dnsx`, `shuffledns`, `alterx`
  - consumes `brute_domain`
  - depends on healthy `resolver` + `redis`

## Unbound Config

`config/unbound/unbound.conf` currently uses:

- `chroot: ""`
- `interface: 0.0.0.0`
- `port: 53`
- `access-control: 172.16.0.0/12 allow`
- `root-hints: "/etc/unbound/named.cache"`

## Target-Level Controls

`targets` table includes:

- `active_recon` (boolean, default false)
- `brute_wordlist` (default `dns-small.txt`)

API supports:

- `POST /targets` with `active_recon`, `brute_wordlist`
- `PATCH /targets/{target_id}` to update these fields

## Runtime Flow

1. `worker-recon` completes passive discovery.
2. If target `active_recon=true`, it enqueues:

```json
{
  "target_id": 1,
  "domain": "example.com",
  "scope_root": "example.com",
  "wordlist": "dns-small.txt"
}
```

to queue `brute_domain` with dedup key `brute:<domain>`.

3. `worker-dns-brute`:
- wildcard checks
- brute force pass
- permutation pass
- scope filtering
- subdomain upsert
- enqueue `probe_host` + `notify_finding`

## Required Host Assets

- `/opt/recon-platform/wordlists/dns-small.txt` (auto-downloaded by init script)
- `/opt/recon-platform/config/unbound/root.hints` (fetched from Internic)

`init-dirs.sh` also repairs the `root.hints` path if it was accidentally created as a directory.

## Operational Verification

```bash
docker compose -p recon-platform -f docker-compose.yml ps
docker compose -p recon-platform -f docker-compose.yml logs -f resolver worker-dns-brute
```

Health expectations:

- `resolver` = healthy
- `worker-dns-brute` = running
