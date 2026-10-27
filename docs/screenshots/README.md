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

How to produce the CI screenshots:

1. Create an empty public repository `secure-notes-api` on GitHub.
2. `git init && git add . && git commit -m "secure notes api" && git branch -M main`
3. `git remote add origin https://github.com/USERNAME/secure-notes-api.git && git push -u origin main`
4. Open **Actions → CI**, wait for all five jobs, screenshot the summary page.
5. Open the `SAST` and `SCA` jobs, screenshot the last 15 lines of the log.
6. Open **Security → Code scanning**, screenshot the (empty) alert list.

Do not screenshot secrets: the `JWT_SECRET` in `.env` is local only and `.env` is
git-ignored.
