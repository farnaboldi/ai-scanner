# AI Scanner — Bench

## Usage
```bash
bench/run.sh up                 # docker compose up + DVWA login/DB-reset/security=low
bench/run.sh scan all           # launch AI Scanner (Burp GUI) against each target,
                                #   exporting findings to results/<target>.report.txt
# ...watch Burp; when each SCAN COMPLETE:
bench/run.sh measure all        # print found/expected % per target
bench/run.sh report             # measure all + write bench/report.md
bench/run.sh down
```
The scanner writes its findings when launched with `AISCANNER_REPORT=<path>` (run.sh sets
it per target) or `-Daiscanner.report=<path>`.
