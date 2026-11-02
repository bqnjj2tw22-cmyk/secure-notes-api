# Screenshots in this repository

The CI evidence is committed here and embedded in the README (section 3.2):

| File | What it shows | Referenced as |
| --- | --- | --- |
| `ci-run.png` | the four jobs of `ci.yml` green on commit `3834cb7` | Figure 1 |
| `sast-sca.png` | Semgrep `0 findings` + `npm audit` output | Figure 2 |
| `code-scanning.png` | Security -> Code scanning: 0 open alerts | Figure 3 |

## CVE-2018-7490 captures (produced when the environment is run)

Start the vulnerable stack from `docs/cve-2018-7490/`:

```bash
docker compose up -d                      # image vulhub/uwsgi-php:2.0.16
curl -s --path-as-is "http://127.0.0.1:8080/..%2f..%2f..%2f..%2f..%2fetc/passwd"
```

then the fixed / filtered stack:

```bash
docker compose -f docker-compose.fixed.yml up -d --build         # uWSGI 2.0.17
# or, without compiling:
docker compose -f docker-compose.demo-fixed.yml up -d            # 2.0.16 + nginx filter, port 8081
curl -s --path-as-is -i "http://127.0.0.1:8081/..%2f..%2f..%2f..%2f..%2fetc/passwd"   # 400
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/                       # 200
```

Save the captures here as:

| File | Content |
| --- | --- |
| `cve-vuln-env.png` | `docker compose ps` showing the container up |
| `cve-exploit.png` | the traversal returning `/etc/passwd` |
| `cve-fixed-env.png` | the fixed (or filtered) stack running |
| `cve-fixed-proof.png` | `400 traversal attempt blocked` followed by `200` for `/` |

Do not screenshot secrets: `.env` is git-ignored and no credential appears in the
repository.
