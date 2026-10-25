# Website image sources

`social-card.html` is the editable source for the 1200 × 630 social preview PNG. Serve the website asset directory at `/` and this file at `/__social-card.html`, then capture the complete 1200 × 630 viewport after fonts and images load. The PNG is an unmodified browser capture. It uses this repository’s existing local fonts and public product assets.

`assets/app-overview.png` is an unmodified browser capture of the real web UI at commit `7c3ca01489c509fc1da4164fb3ecf1abdab53ae3`, served with fictional devices, example domains and synthetic connection data. It does not expose a real router or user traffic.

`brand/fonts/chinese-extra-*.ttf` supplements the existing Noto Sans SC subsets for new page text. The source is [Google Fonts Noto Sans SC](https://github.com/google/fonts/tree/main/ofl/notosanssc), under the existing SIL Open Font License in `brand/fonts/`. The CSS declares only the added Unicode code points.
