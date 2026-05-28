# Add PHP `trackingreportservice` with Path Traversal vulnerability

**Status:** Draft
**Date:** 2026-05-28
**Author:** Brian Sowers
**Branch context:** `add-php-service` (existing branch on origin) + new work in `feature/aiservice` or fresh branch

## Purpose

Cargo Cats currently demonstrates the Contrast agent across Java, Python, .NET, and Node.js. Adding a PHP service closes a meaningful language gap for sales demos and shows the breadth of the Contrast Flex Agent.

An existing branch (`add-php-service`) introduces a Symfony PHP service called `trackingreportservice`, but its sole vulnerability is **XPath Injection**, which is detected by Contrast **Assess only** — there is no Protect/RASP rule for XPath injection in any Contrast language agent. This undercuts the dual Assess + Protect story that the rest of cargo-cats supports.

This spec replaces the XPath Injection demo with a **Path Traversal** demo, which has both Assess and Protect coverage in the PHP agent.

## Goals

- Ship a PHP service instrumented by the Contrast PHP agent (via the existing agent-operator config).
- Demonstrate Contrast **Assess** detecting Path Traversal (taint flow from HTTP query parameter to file read).
- Demonstrate Contrast **Protect** blocking the same Path Traversal attack at runtime.
- Integrate cleanly with the existing topology: `frontgateservice` proxies, `console-ui` drives normal + exploit traffic, helm chart deploys it.
- Match the quality bar of existing services in this repo (this app is used in live sales demos and is public on GitHub).

## Non-goals

- No new vulnerability types beyond Path Traversal. Keeping the vuln story single and crisp.
- No PDF generation, real templating engine, or new persistence layer. The service uses flat files on disk + the existing shared MySQL database.
- No expansion of console-ui beyond what's needed to drive normal and exploit traffic for this service.
- No changes to other vulnerable services.

## Background: why Path Traversal (and not the alternatives)

The four PHP-agent Protect-covered options considered:

| Option | Existing cargo-cats coverage | Fit for this service |
|---|---|---|
| SQL Injection | dataservice (Java) | Awkward — would require a second SQLi sink alongside the existing prepared-statement code |
| Command Injection | webhookservice (Python) | Forced — no natural place to shell out |
| Untrusted Deserialization | frontgateservice (Java) | Plausible (cookies/headers) but adds new attack surface |
| **Path Traversal** | imageservice (.NET) | **Natural** — the service already writes XML reports to disk |

"Unsafe File Upload" was considered as a net-new vulnerability type to cargo-cats, but the PHP Contrast agent does not currently provide an Assess rule for it. Since the goal is to showcase both Assess and Protect, options without dual coverage are out of scope.

Path Traversal duplicates a vulnerability *type* already present in imageservice, but it is the first **PHP** example. Cross-language coverage demonstrating that the same vuln class is caught in a different runtime is itself valuable for the demo.

## Service overview

**Name:** `trackingreportservice`
**Language/framework:** PHP 8 / Symfony 7
**Container:** Apache + `mod_php`
**Port:** 80 (inside cluster)
**Purpose in the demo narrative:** Generates and serves persisted tracking reports for individual shipments. Pulls current shipment status from the shared MySQL database and merges it with locally-stored event history written to per-shipment files on disk.

### Endpoints

| Method | Path | Purpose | Vulnerability |
|---|---|---|---|
| GET | `/api/health` | Liveness probe | None |
| GET | `/api/tracking-report?tracking_id=<id>` | Return full tracking report (events + status) as JSON | None — XPath sink removed and replaced with safe DOM iteration |
| POST | `/api/tracking-report/events` | Append a tracking event to a shipment | None — already uses `htmlspecialchars(..., ENT_XML1)` |
| **GET** | **`/api/tracking-report/download?file=<name>`** | **Stream a saved report file from disk** | **Path Traversal (Assess + Protect)** |

The `/api/tracking-report/search` endpoint from the existing branch is **removed** entirely. Its only purpose was to demonstrate XPath injection, and it does not contribute to the legitimate service narrative.

### Data on disk

The service writes two kinds of files under `var/reports/`:

- `var/reports/tracking_history.xml` — single aggregate XML file (unchanged from current branch)
- `var/reports/exports/TRACK-<id>.txt` — per-shipment plain-text reports, seeded at container start for each of the five sample shipments

The `exports/` directory is the target of the path-traversal sink. Seeded files give the endpoint legitimate content to serve so the demo can show both normal and malicious traffic.

## The vulnerability: Path Traversal

### Vulnerable code (sketch)

```php
#[Route('/tracking-report/download', methods: ['GET'])]
public function downloadReport(Request $request): Response
{
    $file = $request->query->get('file', '');
    if ($file === '') {
        return $this->json(['error' => 'file query parameter is required'], 400);
    }

    // VULNERABLE: $file is concatenated directly to the base path.
    // No realpath() check, no basename() stripping, no allowlist.
    $path = __DIR__ . '/../../var/reports/exports/' . $file;

    if (!file_exists($path)) {
        return $this->json(['error' => 'Report not found'], 404);
    }

    return new Response(
        file_get_contents($path),
        200,
        ['Content-Type' => 'text/plain']
    );
}
```

### Why this works for the demo

- **Assess (IAST):** The Contrast PHP agent tracks taint from `Request::query->get` through the string concatenation to the `file_get_contents` sink, producing a Path Traversal finding with full data-flow trace.
- **Protect (RASP):** The PHP agent has a Path Traversal Protect rule that inspects the resolved file path at the sink and blocks reads that escape the intended base directory.

### Exploit payload

```
GET /api/tracking-report/download?file=../../../../etc/passwd
```

With Protect **off**, returns the contents of `/etc/passwd`.
With Protect **on**, the agent blocks the request and returns an HTTP error (the exact status depends on Protect's configured mode — block vs. monitor).

### Normal (benign) traffic

```
GET /api/tracking-report/download?file=TRACK-A1B2C3D4.txt
```

Returns the seeded plain-text report for that shipment.

## Architecture & integration

### Cluster topology (no change to overall shape)

```
User → nginx-ingress (ModSec WAF) → frontgateservice (Java)
                                        └─→ trackingreportservice (PHP)
                                              ├─→ MySQL (shipment metadata)
                                              └─→ local disk (report files)
```

### Frontgate proxy changes

`TrackingReportServiceProxy.java` on the existing branch has four methods. Final set:

| Method | Action |
|---|---|
| `healthCheck()` | Keep |
| `getTrackingReport(String trackingId)` | Keep |
| `addTrackingEvent(Map<String, Object> body)` | Keep |
| `searchTrackingHistory(String q)` | **Remove** |
| `downloadReport(String file)` | **Add** — returns `ResponseEntity<byte[]>` with content-type propagated |

`ApiController` route changes mirror the proxy: remove the `/search` route, add `/download`.

### Console-ui changes

The existing branch added ~200 lines to `console-ui/app.py` for XPath traffic and exploit endpoints. Reshape that:

- **Normal traffic generator:** mix of `GET /api/tracking-report?tracking_id=<id>`, `POST /api/tracking-report/events`, and **`GET /api/tracking-report/download?file=TRACK-*.txt`** using the seeded filenames.
- **Exploit traffic generator:** sends `GET /api/tracking-report/download?file=../../../../etc/passwd` (and a couple of variations like URL-encoded `..%2F..%2F..%2Fetc%2Fpasswd`).
- Remove XPath-specific exploit buttons and traffic.
- Add a single index.html entry for the new service (pattern matches existing services).

### Helm chart

The existing `cargocats/templates/trackingreportservice.yaml` and `values.yaml` entries are retained. No changes expected beyond ensuring the agent-operator label/annotation lines up with the existing `contrast-agent-operator-config.yaml` PHP agent injector config (already added on the branch).

### Makefile

The branch already added `trackingreportservice` to the build/deploy targets. Keep as-is.

## Documentation updates

1. **README.md**
   - Update the mermaid diagram: replace the (yet to be added) XPath label on `trackingreportservice` with `⚠️ Path Traversal`, language label `PHP`. Apply the same `vuln` classDef coloring used for other services.
   - Add `trackingreportservice` to the "Vulnerable Application Services" prose list.
   - Add "Path Traversal (PHP)" to the vulnerabilities bullet list. Note: imageservice already has a Path Traversal entry — the new entry should make clear it's the PHP example.

2. **vulnerabilities.md**
   - Add a new section for Path Traversal in `trackingreportservice` with: vulnerable endpoint, sink code excerpt, exploit payload, expected Assess finding, expected Protect block.

3. **Branch cleanup**
   - The single squashed `init` commit on `add-php-service` will be amended/replaced as part of this work. Final history should be a small handful of clean commits: (1) add PHP service skeleton + helm + frontgate proxy, (2) add path-traversal endpoint + seed data, (3) console-ui wiring, (4) README + vulnerabilities.md updates.

## Testing & verification

This is a demo app — no automated tests in the existing services to mirror. Verification is manual:

- `make deploy` succeeds and the new pod reaches Ready.
- `kubectl logs` shows the Contrast PHP agent loaded and reporting.
- `curl http://app.localhost/api/tracking-report?tracking_id=TRACK-A1B2C3D4` returns a populated JSON report (exact frontgate path TBD per Open Questions).
- `curl http://app.localhost/api/tracking-report/download?file=TRACK-A1B2C3D4.txt` returns the seeded text file.
- `curl 'http://app.localhost/api/tracking-report/download?file=../../../../etc/passwd'` returns `/etc/passwd` contents **when Protect is disabled**.
- Same request with Protect **enabled** is blocked.
- Contrast Assess UI shows a Path Traversal finding tied to the exploit traffic.
- Console-ui's normal traffic generator produces no Assess/Protect alerts; exploit generator produces both.

## Open questions

None that block implementation. The exact final URL path under `/api/` on `frontgateservice` (`/api/tracking/report/download` vs `/api/tracking-report/download`) should match the convention used by the rest of `ApiController` — to be verified at implementation time.

## Risks

- **PHP agent maturity:** If the PHP agent's Path Traversal Protect rule has gaps (e.g., doesn't fire for certain `file_get_contents` invocations), the demo could fail silently. Mitigation: verify end-to-end on the target Contrast environment before merging.
- **Demo confusion:** Two services with Path Traversal (imageservice .NET + trackingreportservice PHP) might prompt the question "why two?" in demos. Mitigation: README framing emphasizes "same vuln class, different language agent."
