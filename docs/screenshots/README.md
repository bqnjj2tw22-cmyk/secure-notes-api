# Screenshot checklist (Lab 1)

Put the PNG files here with these names. The report refers to them by figure
number, so the numbering below must be kept.

| File | What to capture | Where it goes in the report |
| --- | --- | --- |
| `ci-run.png` | GitHub → Actions → latest CI run: all jobs green (`Tests`, `SAST`, `SCA`, `CodeQL`) | Figure 3 |
| `sast-semgrep.png` | Semgrep job log, final lines (`0 findings`, `Ran 1 rule...`) | Figure 4 |
| `sca-npm-audit.png` | `SCA` job log with `found 0 vulnerabilities` | Figure 4 |
| `code-scanning.png` | Security → Code scanning: no open alerts | Figure 5 |
| `cve-vuln-env.png` | `docker compose ps` of `vulhub/uwsgi/CVE-2018-7490` + phpinfo page in a browser | Figure 6 |
| `cve-exploit.png` | terminal: `curl --path-as-is .../..%2f..%2f..%2f..%2f..%2fetc/passwd` returning `root:x:0:0:...` | Figure 7 |
| `cve-fixed-env.png` | `docker compose -f docker-compose.fixed.yml up --build -d` finishing and `ps` showing both containers | Figure 8 |
| `cve-fixed-proof.png` | terminal: `HTTP/1.1 400 Bad Request` + `traversal attempt blocked`, then `200` for `/` and `/index.php` | Figure 9 |
| `api-curl.png` | optional: Postman/terminal showing login + authenticated `GET /api/data` | Figure 2 |

How to produce the CI screenshots (the repository is already published):

1. Open <https://github.com/bqnjj2tw22-cmyk/secure-notes-api/actions>.
2. Open the newest **CI** run, wait for all jobs, screenshot the run summary.
3. Open the `SAST` job and the `SCA` job, screenshot the last ~15 log lines of each.
4. Open <https://github.com/bqnjj2tw22-cmyk/secure-notes-api/security/code-scanning>,
   screenshot the alert list.

Do not screenshot secrets: the `JWT_SECRET` in `.env` is local only and `.env` is
git-ignored.
