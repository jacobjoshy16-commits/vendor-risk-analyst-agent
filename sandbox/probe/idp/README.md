# Recorded IdP pages

These files are **not** a hand-copied single curl. They are a page set: each
entry is one management-API response the live client would have received,
including `Link: rel="next"` (Okta) or `page` / `include_totals` (Auth0).

`src/vra/idp.py` walks them with the same parser as live HTTP.

```bash
python3 vra.py discover --fixture sandbox/probe/idp/okta_pages.json --dry-run
python3 vra.py discover --fixture sandbox/probe/idp/auth0_pages.json --dry-run
```

A real tenant is:

```bash
export OKTA_API_TOKEN=...
python3 vra.py discover --provider okta --base-url https://your-org.okta.com
```
