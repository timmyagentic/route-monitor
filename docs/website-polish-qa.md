# Website polish QA — 2026-10-25

A real web UI capture uses fictional network data. Mobile installation text is larger and the portfolio footer is no longer duplicated.

Validated in a local browser at 1440 × 1000 and 390 × 844; the page also has no horizontal overflow at 320 px. Visible images loaded. Social metadata resolves to a 1200 × 630 image. Screenshots below are unmodified browser captures of the candidate.

Checks passed: `./qa/check.sh`, `./qa/build-smoke.sh`, JavaScript syntax and Wrangler dry run.

This is website acceptance. Live installation, authentication, production hardware/network operations, and native client acceptance are outside this change. A successful local check does not prove production deployment; the reviewed commit must be deployed and read back separately.

![Desktop candidate](website-polish-preview.png)

![Mobile candidate](website-polish-mobile.png)
