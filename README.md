# DSDC API Compliance Checker

A GitHub Pages tool for implementers. It checks an OpenAPI YAML against a published DSDC **Less-Than-Truckload (LTL)** or **Full Truckload (FTL)** standard and reports whether it passes, along with every breaking issue, warning and additional item. The result is also emailed to the DSDC team.

**Live site:** https://dsdcapis.github.io/api-compliance-checker/

## What it checks

| Area | Examples |
|---|---|
| **Paths & operations** | Missing paths/methods (breaking), additional paths (info), path prefix added in front of standard paths |
| **Fields** | Missing required fields (breaking), missing optional fields (warning), additional fields (info), type/format/enum/length/pattern differences, `allOf`/`oneOf` handling |
| **Field requirements** | Field or parameter optional in the standard but required by you (breaking for requests), required response fields marked optional |
| **Terminology** | Renamed or misspelled fields, parameters, paths and code values (`pro_number` vs `proNumber`, `CREATE` vs `Create`), naming-convention drift, differing operationIds |
| **HTTP** | Success status codes, content types, response headers, trailing slashes, bodies on GET/DELETE/204, duplicate operationIds, server URLs |
| **Security** | Authentication defined and applied, HTTPS only, standard's auth methods supported, API keys in query strings, HTTP Basic, deprecated OAuth flows, 401 documented, credentials or card numbers embedded in examples |
| **Error handling** | 4xx/5xx documented, 400 for inputs, 404 for path-addressed resources, error bodies have a schema, consistent error model, standard's error format (e.g. `application/problem+json`), 429 rate limiting |

Direction matters. In a **request**, your API must accept everything the standard allows. In a **response**, it must send only what the standard allows. So an extra enum value is harmless in a request but breaking in a response.

**Verdict:** `FAIL` if there is any breaking issue, `PASS WITH WARNINGS` if there are warnings only, otherwise `PASS`.

> HTTP, security and error-handling rules are a **DSDC baseline** applied to every submission. The published standards mostly don't define these areas yet (for example, only LTL In-Transit Visibility declares `securitySchemes`). Where a standard does define them, the submission is also compared against it. Severities live in [`src/engine/baseline.js`](src/engine/baseline.js) and should be confirmed by the committees.

## How data is handled

- The YAML is parsed and compared **in the submitter's browser**. Nothing is uploaded while they work.
- Running a check sends the results to the DSDC team. The YAML is included only if the submitter leaves *Share my YAML* checked.
- Before anything is sent, values that look like credentials (JWTs, API keys, bearer tokens, private keys, passwords in examples) and **payment card numbers** (Luhn-checked) are replaced with `***REDACTED***`. Server hostnames are masked by default. The submitter can open *What was sent to DSDC* to see the exact payload.
- The page has a strict Content-Security-Policy: no third-party scripts, and network access only to the configured notification endpoint. All page code is bundled from this repo; no CDN is used.
- Every value from the submission is rendered as text, never as HTML.
- The recipient email address is configured inside the notification service, not in this public repo, so it can't be harvested.

## Setting up the email notification

GitHub Pages is static and can't send email itself, so the page posts the result to a form relay that emails it to you. Pick one, then set **repository variables** (Settings → Secrets and variables → Actions → *Variables*) and re-run the workflow.

| Provider | Setup | Variables |
|---|---|---|
| **Web3Forms** (recommended: does not store submissions) | Create an access key at web3forms.com for the recipient address | `NOTIFY_PROVIDER=web3forms`, `NOTIFY_ACCESS_KEY=<key>` |
| **Formspree** | Create a form for the recipient address | `NOTIFY_PROVIDER=formspree`, `NOTIFY_ENDPOINT=https://formspree.io/f/<id>` |
| **Power Automate / any webhook** | Flow: *When an HTTP request is received* → *Send an email (V2)* using `subject` and `text` from the JSON body | `NOTIFY_PROVIDER=webhook`, `NOTIFY_ENDPOINT=<https URL>` |

Until this is configured, the site still works and shows results to the submitter. It says that notifications are not enabled.

Free relay tiers cap monthly submissions and message size. The email includes the first 150 findings and up to 250 KB of YAML; the submitter can download the full report.

## Where the standards come from

[`config/sources.json`](config/sources.json) lists the **public** standards repos. At build time, [`scripts/build-standards.mjs`](scripts/build-standards.mjs) clones them and finds every root OpenAPI document under `api-specs/<api>/<version>/`. It bundles external `$ref`s (such as FTL's `schemas/schemas.yaml`) into one file per standard and writes a manifest. The newest version of each API is pre-selected.

The site rebuilds on every push, weekly, on demand (*Actions → Build and deploy checker → Run workflow*), and when a standards repo sends a `repository_dispatch` of type `standards-updated`.

Only add public repos to `sources.json`. Everything built is published.

## Development

```bash
npm ci
npm test                 # engine unit tests
npm run build            # fetch standards + build site into dist/
npm run selfcheck        # each standard compared with itself must produce no diff findings
npm run serve            # http://localhost:8080
```

Behind a TLS-inspecting proxy, prefix commands with `NODE_OPTIONS=--use-system-ca`.

| Path | Purpose |
|---|---|
| `src/engine/` | Comparison engine. Dependency-free; runs in the browser and in Node |
| `src/app/` | Page logic and notification relay |
| `site/` | HTML, CSS, icon |
| `scripts/` | Standards bundler, site builder, self-check, local server |
| `test/` | Unit tests |

## Limitations

- The checker compares **definitions**, not live traffic. A pass doesn't certify the running API.
- Multi-file specs must be bundled into one file first (e.g. `npx @redocly/cli bundle openapi.yaml`). Unresolvable `$ref`s are reported, and anything behind them isn't checked.
- Swagger 2.0 must be converted to OpenAPI 3.x first.
