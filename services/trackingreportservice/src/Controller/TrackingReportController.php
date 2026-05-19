<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/api', name: 'api_')]
class TrackingReportController extends AbstractController
{
    private string $xmlFilePath;

    public function __construct()
    {
        $this->xmlFilePath = __DIR__ . '/../../var/reports/tracking_history.xml';
        $this->initializeXmlFile();
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
                ['2025-09-03T09:00:00Z', 'Chicago, IL',  'pickup',  'Package picked up from sender'],
                ['2025-09-03T18:00:00Z', 'St. Louis, MO', 'transit', 'Arrived at sorting facility'],
                ['2025-09-04T06:30:00Z', 'Dallas, TX',   'transit', 'Out for final delivery leg'],
            ]);

            $this->addSampleShipment($xml, $root, 'TRACK-I9J0K1L2', 'Shadow', 'Seattle, WA', 'Miami, FL', 'delivered', [
                ['2025-08-28T07:00:00Z', 'Seattle, WA',   'pickup',   'Package picked up from sender'],
                ['2025-08-28T19:00:00Z', 'Portland, OR',  'transit',  'Departed sorting facility'],
                ['2025-08-29T11:00:00Z', 'Sacramento, CA','transit',  'Customs inspection cleared'],
                ['2025-08-30T09:00:00Z', 'Phoenix, AZ',   'transit',  'Arrived at regional hub'],
                ['2025-08-31T08:00:00Z', 'Atlanta, GA',   'transit',  'Final sorting complete'],
                ['2025-08-31T15:30:00Z', 'Miami, FL',     'delivery', 'Delivered to recipient'],
            ]);

            $this->addSampleShipment($xml, $root, 'TRACK-M3N4O5P6', 'Luna', 'Boston, MA', 'Portland, OR', 'processing', [
                ['2025-09-04T10:00:00Z', 'Boston, MA', 'pickup', 'Package picked up from sender'],
            ]);

            $this->addSampleShipment($xml, $root, 'TRACK-Q7R8S9T0', 'Oliver', 'Austin, TX', 'Denver, CO', 'delivered', [
                ['2025-09-01T11:00:00Z', 'Austin, TX',  'pickup',   'Package picked up from sender'],
                ['2025-09-02T03:00:00Z', 'Dallas, TX',  'transit',  'Departed sorting facility'],
                ['2025-09-02T14:00:00Z', 'Albuquerque, NM', 'transit', 'In transit'],
                ['2025-09-03T09:30:00Z', 'Denver, CO',  'delivery', 'Delivered to recipient'],
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

        $xpath          = new \DOMXPath($xml);
        $existingNodes  = $xpath->query("//shipment[@trackingId='" . htmlspecialchars($trackingId, ENT_XML1) . "']");

        if ($existingNodes->length > 0) {
            // Update status only — preserve existing event history
            $shipmentNode = $existingNodes->item(0);
            $statusNode   = $shipmentNode->getElementsByTagName('currentStatus')->item(0);
            if ($statusNode) {
                $statusNode->textContent = $row['status'] ?? 'unknown';
            }
        } else {
            // Insert new shipment with no events
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

    /**
     * Returns the full event history for a shipment as a structured tracking report.
     *
     * VULNERABLE: The tracking_id query parameter is interpolated directly into
     * the XPath query without sanitization, allowing XPath injection attacks.
     * An attacker can escape the attribute predicate and inject arbitrary XPath
     * expressions to traverse or dump the entire XML document.
     *
     * Example payload: ?tracking_id=TRACK-A1B2C3D4' or '1'='1
     */
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

        $xpath = new \DOMXPath($xml);

        // VULNERABLE: Direct XPath injection — trackingId is not sanitized
        $query = "//shipment[@trackingId='$trackingId']";
        $results = $xpath->query($query);

        if ($results === false || $results->length === 0) {
            return $this->json(['error' => 'No tracking history found for the given tracking ID'], 404);
        }

        $shipmentNode = $results->item(0);

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
     * Search tracking history by tracking ID fragment or origin/destination city.
     *
     * VULNERABLE: The search term is interpolated directly into the XPath query.
     */
    #[Route('/tracking-report/search', name: 'tracking_report_search', methods: ['GET'], priority: 10)]
    public function searchTrackingHistory(Request $request): JsonResponse
    {
        $term = $request->query->get('q', '');

        if (empty($term)) {
            return $this->json(['error' => 'Search term is required'], 400);
        }

        try {
            $xml = new \DOMDocument();
            $xml->load($this->xmlFilePath);

            $xpath = new \DOMXPath($xml);

            // VULNERABLE: Direct XPath injection — $term concatenated without sanitization
            $termLower = strtolower($term);
            $query = "//shipment[" .
                "contains(translate(@trackingId,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'$termLower') or " .
                "contains(translate(origin,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'$termLower') or " .
                "contains(translate(destination,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'$termLower') or " .
                "contains(translate(cat,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'$termLower')" .
            "]";

            $results = $xpath->query($query);

            $shipments = [];
            foreach ($results as $shipmentNode) {
                $shipments[] = [
                    'tracking_id'    => $shipmentNode->getAttribute('trackingId'),
                    'cat'            => $shipmentNode->getElementsByTagName('cat')->item(0)->textContent,
                    'origin'         => $shipmentNode->getElementsByTagName('origin')->item(0)->textContent,
                    'destination'    => $shipmentNode->getElementsByTagName('destination')->item(0)->textContent,
                    'current_status' => $shipmentNode->getElementsByTagName('currentStatus')->item(0)->textContent,
                    'event_count'    => $shipmentNode->getElementsByTagName('event')->length,
                ];
            }

            return $this->json([
                'search_term' => $term,
                'query_used'  => $query,
                'results'     => $shipments,
                'count'       => count($shipments),
            ]);

        } catch (\Exception $e) {
            return $this->json([
                'error'           => 'Search failed',
                'message'         => $e->getMessage(),
                'query_attempted' => $query ?? 'unknown',
            ], 500);
        }
    }

    /**
     * Append a new tracking event to an existing shipment record.
     */
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

        $xpath = new \DOMXPath($xml);
        $shipmentNodes = $xpath->query("//shipment[@trackingId='" . htmlspecialchars($trackingId, ENT_XML1) . "']");

        if ($shipmentNodes->length === 0) {
            return $this->json(['error' => 'Shipment not found'], 404);
        }

        $shipmentNode = $shipmentNodes->item(0);
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

        // Update currentStatus if type is delivery
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
