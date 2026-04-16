package com.contrast.frontgateservice.controller;

import com.contrast.frontgateservice.entity.User;
import com.contrast.frontgateservice.service.DataServiceProxy;
import com.contrast.frontgateservice.service.ImageServiceProxy;
import com.contrast.frontgateservice.service.WebhookServiceProxy;
import com.contrast.frontgateservice.service.UserService;
import com.contrast.frontgateservice.service.LabelServiceProxy;
import com.contrast.frontgateservice.service.DocServiceProxy;
import com.contrast.frontgateservice.service.ReportServiceProxy;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.Map;
import java.util.List;
import java.io.*;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api")
public class ApiController {

    private static final Logger logger = LogManager.getLogger(ApiController.class);

    @Autowired
    private DataServiceProxy dataServiceProxy;
    
    @Autowired
    private ImageServiceProxy imageServiceProxy;
    
    @Autowired
    private WebhookServiceProxy webhookServiceProxy;
    
    @Autowired
    private LabelServiceProxy labelServiceProxy;
    
    @Autowired
    private DocServiceProxy docServiceProxy;
    
    @Autowired
    private ReportServiceProxy reportServiceProxy;
    
    @Autowired
    private UserService userService;

    @GetMapping("/cats") 
    public ResponseEntity<String> getCats() {
        // Get the current authenticated user
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        logger.info("API request: Getting cats for user {}", username);
        
        // Look up the user ID from the UserService
        User user = userService.findByUsername(username);
        if (user != null) {
            logger.debug("Found user ID {} for username {}", user.getId(), username);
            // Get cats filtered by the current user's ID
            ResponseEntity<String> response = dataServiceProxy.getCatsByOwner(user.getId());
            logger.info("Retrieved cats for user {}, status: {}", username, response.getStatusCode());
            return ResponseEntity.ok()
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body(response.getBody());
        } else {
            logger.warn("User not found for username: {}", username);
            // If user not found, return empty result
            return ResponseEntity.ok()
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"_embedded\":{\"cats\":[]}}");
        }
    }

    @PostMapping("/cats")
    public ResponseEntity<String> createCat(@RequestBody Map<String, Object> catData) {
        // Get the current authenticated user
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        logger.info("API request: Creating new cat for user {}", username);
        logger.debug("Cat data: {}", catData);
        
        // Look up the user ID from the UserService
        User user = userService.findByUsername(username);
        if (user != null) {
            logger.debug("Found user ID {} for username {}", user.getId(), username);
            // Add the objOwner field as a URI reference for Spring Data REST
            catData.put("objOwner", "/users/" + user.getId());
        } else {
            logger.warn("User not found for username: {}", username);
        }
        
        ResponseEntity<String> response = dataServiceProxy.createCat(catData);
        logger.info("Created cat for user {}, status: {}", username, response.getStatusCode());
        return ResponseEntity.status(response.getStatusCode())
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .body(response.getBody());
    }

    // vuln, userid is not checked when deleteing
    @GetMapping("/cats/{id}")
    public ResponseEntity<String> getCat(@PathVariable String id) {
        logger.info("API request: Getting cat with ID {}", id);
        
        ResponseEntity<String> response = dataServiceProxy.getCat(id);
        logger.info("Retrieved cat with ID {}, status: {}", id, response.getStatusCode());
        
        return ResponseEntity.status(response.getStatusCode())
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .body(response.getBody());
    }

    @DeleteMapping("/cats/{id}")
    public ResponseEntity<String> deleteCat(@PathVariable String id) {
        logger.info("API request: Deleting cat with ID {}", id);
        
        ResponseEntity<String> response = dataServiceProxy.deleteCat(id);
        logger.info("Deleted cat with ID {}, status: {}", id, response.getStatusCode());
        
        return ResponseEntity.status(response.getStatusCode())
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .body(response.getBody());
    }

    // Shipment tracking endpoints
    @GetMapping("/shipments/track")
    public ResponseEntity<String> trackShipment(@RequestParam String trackingId) {
        
        logger.info("API request: Tracking shipment with ID {}", trackingId);
        logger.debug("Tracking ID length: {}", trackingId.length());
        logger.trace("Tracking ID bytes: {}", java.util.Arrays.toString(trackingId.getBytes()));
        
        ResponseEntity<String> response = dataServiceProxy.getShipmentByTrackingId(trackingId);
        logger.debug("DataService response status: {}", response.getStatusCode());
        logger.trace("DataService response body: {}", response.getBody());
        
        if (response.getStatusCode().is2xxSuccessful()) {
            try {
                logger.debug("Parsing JSON response...");
                // Parse the JSON response
                ObjectMapper mapper = new ObjectMapper();
                JsonNode rootNode = mapper.readTree(response.getBody());
                JsonNode embeddedNode = rootNode.get("_embedded");
                
                if (embeddedNode != null && embeddedNode.has("shipments")) {
                    JsonNode shipmentsNode = embeddedNode.get("shipments");
                    logger.debug("Found shipments node, array size: {}", shipmentsNode.size());
                    
                    if (shipmentsNode.isArray() && shipmentsNode.size() > 0) {
                        JsonNode shipment = shipmentsNode.get(0);
                        String trackingIdValue = shipment.get("trackingId").asText();
                        String status = shipment.get("status").asText();
                        
                        logger.debug("Found shipment - trackingId: {}, status: {}", trackingIdValue, status);
                        
                        // Get status badge class
                        String badgeClass = getStatusBadgeClass(status);
                        String statusText = status.substring(0, 1).toUpperCase() + status.substring(1);
                        
                        // Build HTML response
                        String html = String.format(
                            "<div class=\"alert alert-success\">" +
                                "<h6><i class=\"fas fa-check-circle me-2\"></i>Shipment Found!</h6>" +
                                "<p class=\"mb-1\"><strong>Tracking ID:</strong> %s</p>" +
                                "<p class=\"mb-1\"><strong>Status:</strong> <span class=\"badge %s\">%s</span></p>" +
                                "<small class=\"text-muted\">Your precious cargo is being tracked! 🐱</small>" +
                            "</div>",
                            trackingIdValue, badgeClass, statusText
                        );
                        
                        logger.debug("Returning success HTML response");
                        return ResponseEntity.ok()
                                .contentType(org.springframework.http.MediaType.TEXT_HTML)
                                .body(html);
                    }
                } else {
                    logger.debug("No _embedded.shipments found in response");
                }
                
                // No shipment found
                logger.info("No shipment found for tracking ID {}, returning 404", trackingId);
                String notFoundHtml = String.format(
                    "<div class=\"alert alert-danger\">" +
                        "<i class=\"fas fa-times-circle me-2\"></i>" +
                        "Tracking ID \"%s\" not found. Please check the ID and try again." +
                    "</div>",
                    trackingId
                );
                
                logger.trace("Generated HTML: {}", notFoundHtml);
                
                return ResponseEntity.status(404)
                        .contentType(org.springframework.http.MediaType.TEXT_HTML)
                        .body(notFoundHtml);
                        
            } catch (Exception e) {
                // Error parsing JSON
                logger.error("Exception parsing JSON for tracking ID {}: {}", trackingId, e.getMessage());
                logger.debug("Stack trace:", e);
                
                String errorHtml = String.format(
                    "<div class=\"alert alert-danger\">" +
                        "<i class=\"fas fa-exclamation-triangle me-2\"></i>" +
                        "Unable to track shipment \"%s\" at this time. Please try again later." +
                    "</div>",
                    trackingId
                );
                
                logger.trace("Generated error HTML: {}", errorHtml);
                
                return ResponseEntity.status(500)
                        .contentType(org.springframework.http.MediaType.TEXT_HTML)
                        .body(errorHtml);
            }
        } else {
            // Handle error response from data service
            logger.warn("DataService returned non-2xx status: {} for tracking ID {}", response.getStatusCode(), trackingId);
            
            String errorHtml = String.format(
                "<div class=\"alert alert-danger\">" +
                    "<i class=\"fas fa-exclamation-triangle me-2\"></i>" +
                    "Unable to track shipment \"%s\" at this time. Please try again later." +
                "</div>",
                trackingId
            );
            
            logger.trace("Generated service error HTML: {}", errorHtml);
            
            return ResponseEntity.status(response.getStatusCode())
                    .contentType(org.springframework.http.MediaType.TEXT_HTML)
                    .body(errorHtml);
        }
    }
    
    private String getStatusBadgeClass(String status) {
        switch(status.toLowerCase()) {
            case "delivered":
                return "bg-success";
            case "in_transit":
            case "in transit":
            case "shipped":
                return "bg-primary";
            case "processing":
            case "preparing":
                return "bg-warning";
            case "cancelled":
            case "failed":
                return "bg-danger";
            case "open":
            case "pending":
                return "bg-secondary";
            default:
                return "bg-info";
        }
    }

    @GetMapping("/shipments")
    public ResponseEntity<String> getMyShipments() {
        // Get the current authenticated user
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        // Look up the user ID from the UserService
        User user = userService.findByUsername(username);
        if (user != null) {
            // Get shipments filtered by the current user's ID
            ResponseEntity<String> response = dataServiceProxy.getShipmentsByOwner(user.getId());
            return ResponseEntity.ok()
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body(response.getBody());
        } else {
            // If user not found, return empty result
            return ResponseEntity.ok()
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"_embedded\":{\"shipments\":[]}}");
        }
    }

    @PostMapping("/shipments")
    public ResponseEntity<String> createShipment(@RequestBody Map<String, Object> shipmentData) {
        // Get the current authenticated user
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        // Look up the user ID from the UserService
        User user = userService.findByUsername(username);
        if (user != null) {
            // Add the objOwner field as a URI reference for Spring Data REST
            shipmentData.put("objOwner", "/users/" + user.getId());
        }
        
        ResponseEntity<String> response = dataServiceProxy.createShipment(shipmentData);
        return ResponseEntity.status(response.getStatusCode())
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .body(response.getBody());
    }

    @PatchMapping("/shipments/{id}/status")
    public ResponseEntity<String> updateShipmentStatus(@PathVariable String id, @RequestBody Map<String, String> statusUpdate) {
        String status = statusUpdate.get("status");
        if (status == null || status.trim().isEmpty()) {
            return ResponseEntity.badRequest()
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Status is required\"}");
        }
        
        ResponseEntity<String> response = dataServiceProxy.updateShipmentStatus(id, status);
        return ResponseEntity.status(response.getStatusCode())
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .body(response.getBody());
    }

    @GetMapping("/shipments/{id}/cat")
    public ResponseEntity<String> getShipmentCat(@PathVariable String id) {
        ResponseEntity<String> response = dataServiceProxy.getShipmentCat(id);
        return ResponseEntity.status(response.getStatusCode())
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .body(response.getBody());
    }

    @GetMapping("/shipments/{id}/fromAddress") 
    public ResponseEntity<String> getShipmentFromAddress(@PathVariable String id) {
        ResponseEntity<String> response = dataServiceProxy.getShipmentFromAddress(id);
        return ResponseEntity.status(response.getStatusCode())
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .body(response.getBody());
    }

    @GetMapping("/shipments/{id}/toAddress")
    public ResponseEntity<String> getShipmentToAddress(@PathVariable String id) {
        ResponseEntity<String> response = dataServiceProxy.getShipmentToAddress(id);
        return ResponseEntity.status(response.getStatusCode())
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .body(response.getBody());
    }

    // Address endpoints
    @GetMapping("/addresses")
    public ResponseEntity<String> getMyAddresses() {
        // Get the current authenticated user
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        // Look up the user ID from the UserService
        User user = userService.findByUsername(username);
        if (user != null) {
            // Get addresses filtered by the current user's ID
            ResponseEntity<String> response = dataServiceProxy.getAddressesByOwner(user.getId());
            return ResponseEntity.ok()
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body(response.getBody());
        } else {
            // If user not found, return empty result
            return ResponseEntity.ok()
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"_embedded\":{\"address\":[]}}");
        }
    }

    @PostMapping("/addresses")
    public ResponseEntity<String> createAddress(@RequestBody Map<String, Object> addressData) {
        // Get the current authenticated user
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        // Look up the user ID from the UserService
        User user = userService.findByUsername(username);
        if (user != null) {
            // Add the objOwner field as a URI reference for Spring Data REST
            addressData.put("objOwner", "/users/" + user.getId());
        }
        
        ResponseEntity<String> response = dataServiceProxy.createAddress(addressData);
        return ResponseEntity.status(response.getStatusCode())
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .body(response.getBody());
    }

    // --- Address Export Functionality ---
    @GetMapping("/addresses/export")
    public void exportAddresses(HttpServletResponse response) {
        try {
            // Get the current authenticated user
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            String username = auth.getName();
            User user = userService.findByUsername(username);
            if (user == null) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
            // Get addresses as Java objects (vulnerable: assumes DataServiceProxy returns List<Address>)
            List<Object> addresses = dataServiceProxy.getAddressesByOwnerAsObjects(user.getId());
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=addresses.ser");
            ObjectOutputStream oos = new ObjectOutputStream(response.getOutputStream());
            oos.writeObject(addresses);
            oos.flush();
            oos.close();
        } catch (Exception e) {
            try {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().write("Export failed: " + e.getMessage());
            } catch (IOException ignored) {}
        }
    }

    // --- Address Import Functionality (VULNERABLE: Untrusted Deserialization) ---
    @PostMapping("/addresses/import")
    public ResponseEntity<String> importAddresses(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest()
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"No file provided\"}");
        }
        try {
            // VULNERABLE: Untrusted deserialization of user-supplied file
            ObjectInputStream ois = new ObjectInputStream(file.getInputStream());
            Object obj = ois.readObject();
            ois.close();
            if (obj instanceof List) {
                List<?> addresses = (List<?>) obj;
                // Get the current authenticated user
                org.springframework.security.core.Authentication auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
                String username = auth.getName();
                com.contrast.frontgateservice.entity.User user = userService.findByUsername(username);
                int saved = 0;
                for (Object addressObj : addresses) {
                    if (addressObj instanceof java.util.Map) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> addressMap = (Map<String, Object>) addressObj;
                        // Remove fields that should not be imported
                        addressMap.remove("id");
                        addressMap.remove("_links");
                        // Set objOwner to current user (as in cat endpoints)
                        if (user != null) {
                            addressMap.put("objOwner", "/users/" + user.getId());
                        }
                        try {
                            dataServiceProxy.createAddress(addressMap);
                            saved++;
                        } catch (Exception ex) {
                            logger.error("Failed to save imported address: {}", ex.getMessage());
                        }
                    }
                }
                logger.info("Imported {} addresses successfully", saved);
                logger.debug("Imported addresses: {}", addresses);
                return ResponseEntity.ok()
                        .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                        .body("{\"message\": \"Addresses imported and saved \", \"saved\": " + saved + "}");
            } else {
                return ResponseEntity.badRequest()
                        .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                        .body("{\"error\": \"Invalid file format\"}");
            }
        } catch (Exception e) {
            logger.error("Address import error: {}", e.getMessage());
            logger.debug("Stack trace:", e);
            return ResponseEntity.status(500)
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Import failed: " + e.getMessage() + "\"}");
        }
    }

    @DeleteMapping("/addresses/{id}")
    public ResponseEntity<String> deleteAddress(@PathVariable String id) {
        ResponseEntity<String> response = dataServiceProxy.deleteAddress(id);
        return ResponseEntity.status(response.getStatusCode())
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .body(response.getBody());
    }

    @PostMapping("/payments/process")
    public ResponseEntity<String> processPayment(@RequestBody Map<String, Object> paymentData) {
        try {
            String shipmentId = paymentData.get("shipmentId").toString();
            String cardNumber = paymentData.get("cardNumber").toString();
            // Call the payment service
            ResponseEntity<String> response = dataServiceProxy.processPayment(cardNumber, shipmentId);
            return ResponseEntity.ok()
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body(response.getBody());
        } catch (Exception e) {
            logger.error("Payment processing error: {}", e.getMessage());
            logger.debug("Stack trace:", e);
            return ResponseEntity.status(500)
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Payment processing failed: " + e.getMessage() + "\"}");
        }
    }

    // Webhook service endpoints
    @PostMapping("/webhook/notify")
    public ResponseEntity<String> sendWebhookNotification(@RequestBody Map<String, Object> webhookData) {
        try {
            ResponseEntity<String> response = webhookServiceProxy.sendWebhookNotification(webhookData);
            return ResponseEntity.status(response.getStatusCode())
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body(response.getBody());
        } catch (Exception e) {
            logger.error("Webhook notification error: {}", e.getMessage());
            logger.debug("Stack trace:", e);
            return ResponseEntity.status(500)
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Webhook notification failed: " + e.getMessage() + "\"}");
        }
    }

    @PostMapping("/webhook/test-connection")
    public ResponseEntity<String> testWebhookConnection(@RequestBody Map<String, Object> connectionData) {
        try {
            ResponseEntity<String> response = webhookServiceProxy.testConnection(connectionData);
            return ResponseEntity.status(response.getStatusCode())
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body(response.getBody());
        } catch (Exception e) {
            logger.error("Webhook connection test error: {}", e.getMessage());
            logger.debug("Stack trace:", e);
            return ResponseEntity.status(500)
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Connection test failed: " + e.getMessage() + "\"}");
        }
    }

    @GetMapping("/webhook/health")
    public ResponseEntity<String> checkWebhookServiceHealth() {
        try {
            ResponseEntity<String> response = webhookServiceProxy.healthCheck();
            return ResponseEntity.status(response.getStatusCode())
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body(response.getBody());
        } catch (Exception e) {
            logger.error("Webhook service health check error: {}", e.getMessage());
            logger.debug("Stack trace:", e);
            return ResponseEntity.status(500)
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Health check failed: " + e.getMessage() + "\"}");
        }
    }

    @PostMapping("/webhook/notify-form")
    public ResponseEntity<String> sendWebhookNotificationForm(
            @RequestParam String url, 
            @RequestParam(required = false, defaultValue = "GET") String method) {
        try {
            ResponseEntity<String> response = webhookServiceProxy.sendWebhookNotificationForm(url, method);
            return ResponseEntity.status(response.getStatusCode())
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body(response.getBody());
        } catch (Exception e) {
            logger.error("Webhook notification (form) error: {}", e.getMessage());
            logger.debug("Stack trace:", e);
            return ResponseEntity.status(500)
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Webhook notification failed: " + e.getMessage() + "\"}");
        }
    }

    @PostMapping("/webhook/test-connection-form")
    public ResponseEntity<String> testWebhookConnectionForm(@RequestParam String url) {
        try {
            ResponseEntity<String> response = webhookServiceProxy.testConnectionForm(url);
            return ResponseEntity.status(response.getStatusCode())
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body(response.getBody());
        } catch (Exception e) {
            logger.error("Webhook connection test (form) error: {}", e.getMessage());
            logger.debug("Stack trace:", e);
            return ResponseEntity.status(500)
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Connection test failed: " + e.getMessage() + "\"}");
        }
    }

    @PatchMapping("/shipments/{id}/webhook")
    public ResponseEntity<String> updateShipmentWebhook(@PathVariable String id, @RequestBody Map<String, String> webhookData) {
        String notificationUrl = webhookData.get("notificationUrl");
        
        ResponseEntity<String> response = dataServiceProxy.updateShipmentWebhook(id, notificationUrl);
        return ResponseEntity.status(response.getStatusCode())
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .body(response.getBody());
    }

    @PostMapping("/webhook/test-shipment-notification")
    public ResponseEntity<String> testShipmentNotification(@RequestBody Map<String, Object> testData) {
        try {
            ResponseEntity<String> response = webhookServiceProxy.testShipmentNotification(testData);
            return ResponseEntity.status(response.getStatusCode())
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body(response.getBody());
        } catch (Exception e) {
            logger.error("Shipment notification test error: {}", e.getMessage());
            logger.debug("Stack trace:", e);
            return ResponseEntity.status(500)
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Shipment notification test failed: " + e.getMessage() + "\"}");
        }
    }

    // Image service endpoints
    @GetMapping("/photos")
    public ResponseEntity<String> getPhotos() {
        ResponseEntity<String> response = imageServiceProxy.getPhotos();
        return ResponseEntity.status(response.getStatusCode())
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .body(response.getBody());
    }

    @PostMapping("/photos/upload")
    public ResponseEntity<String> uploadPhoto(@RequestParam("file") org.springframework.web.multipart.MultipartFile file) {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest()
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"No file provided\"}");
        }
        
        ResponseEntity<String> response = imageServiceProxy.savePhoto(file);
        return ResponseEntity.status(response.getStatusCode())
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .body(response.getBody());
    }

    @GetMapping("/photos/view")
    public ResponseEntity<byte[]> viewPhoto(@RequestParam String path) {
        ResponseEntity<byte[]> response = imageServiceProxy.getPhoto(path);
        return ResponseEntity.status(response.getStatusCode())
                .contentType(org.springframework.http.MediaType.parseMediaType("image/jpeg")) // Default to JPEG, could be improved
                .body(response.getBody());
    }

    // Label service endpoints
    @PostMapping("/labels/generate")
    public ResponseEntity<byte[]> generateShippingLabel(@RequestBody Map<String, Object> labelData) {
        try {
            // Validate that we have at least some recipient information
            String firstName = (String) labelData.get("firstName");
            String lastName = (String) labelData.get("lastName");
            String address = (String) labelData.get("address");
            
            if ((firstName == null || firstName.trim().isEmpty()) && 
                (lastName == null || lastName.trim().isEmpty()) && 
                (address == null || address.trim().isEmpty())) {
                return ResponseEntity.badRequest().body(null);
            }

            ResponseEntity<byte[]> response = labelServiceProxy.generateLabel(labelData);
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return ResponseEntity.ok()
                        .contentType(org.springframework.http.MediaType.APPLICATION_PDF)
                        .header("Content-Disposition", "attachment; filename=\"shipping-label.pdf\"")
                        .body(response.getBody());
            } else {
                return ResponseEntity.status(response.getStatusCode()).body(null);
            }
        } catch (Exception e) {
            logger.error("Label generation error: {}", e.getMessage());
            logger.debug("Stack trace:", e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @GetMapping("/labels/health")
    public ResponseEntity<String> checkLabelServiceHealth() {
        try {
            ResponseEntity<String> response = labelServiceProxy.healthCheck();
            return ResponseEntity.status(response.getStatusCode())
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body(response.getBody());
        } catch (Exception e) {
            logger.error("Label service health check error: {}", e.getMessage());
            logger.debug("Stack trace:", e);
            return ResponseEntity.status(500)
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Health check failed: " + e.getMessage() + "\"}");
        }
    }

    @GetMapping("/labels/example")
    public ResponseEntity<String> getLabelServiceExample() {
        try {
            ResponseEntity<String> response = labelServiceProxy.getExample();
            return ResponseEntity.status(response.getStatusCode())
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body(response.getBody());
        } catch (Exception e) {
            logger.error("Label service example error: {}", e.getMessage());
            logger.debug("Stack trace:", e);
            return ResponseEntity.status(500)
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Example request failed: " + e.getMessage() + "\"}");
        }
    }

    // Document service endpoints
    @PostMapping("/documents/process")
    public ResponseEntity<String> processDocument(@RequestParam("file") org.springframework.web.multipart.MultipartFile file) {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest()
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"No file provided\"}");
        }
        
        if (!file.getOriginalFilename().toLowerCase().endsWith(".docx")) {
            return ResponseEntity.badRequest()
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Only DOCX files are supported\"}");
        }
        
        try {
            ResponseEntity<String> response = docServiceProxy.processDocx(file);
            return ResponseEntity.status(response.getStatusCode())
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body(response.getBody());
        } catch (Exception e) {
            logger.error("Document processing error: {}", e.getMessage());
            logger.debug("Stack trace:", e);
            return ResponseEntity.status(500)
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Document processing failed: " + e.getMessage() + "\"}");
        }
    }

    @GetMapping("/documents/health")
    public ResponseEntity<String> checkDocumentServiceHealth() {
        try {
            ResponseEntity<String> response = docServiceProxy.healthCheck();
            return ResponseEntity.status(response.getStatusCode())
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body(response.getBody());
        } catch (Exception e) {
            logger.error("Document service health check error: {}", e.getMessage());
            logger.debug("Stack trace:", e);
            return ResponseEntity.status(500)
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Health check failed: " + e.getMessage() + "\"}");
        }
    }

    /**
     * Get a random cat fact from catfact.ninja API
     * @return ResponseEntity with a random cat fact in JSON format
     */
    @GetMapping("/cats/facts")
    public ResponseEntity<String> getCatFact() {
        logger.info("API request: Getting random cat fact");
        
        try {
            String url = "https://catfact.ninja/fact";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
            
            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
            
            logger.info("Retrieved cat fact, status: {}", response.getStatusCode());
            logger.debug("Cat fact response: {}", response.getBody());
            
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(response.getBody());
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            logger.error("Error retrieving cat fact: {} - {}", e.getStatusCode(), e.getMessage());
            return ResponseEntity.status(e.getStatusCode())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Failed to retrieve cat fact: " + e.getMessage() + "\"}");
        } catch (Exception e) {
            logger.error("Error retrieving cat fact: {}", e.getMessage());
            logger.debug("Stack trace:", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Failed to retrieve cat fact: " + e.getMessage() + "\"}");
        }
    }

    // Report service endpoints
    @PostMapping("/reports/generate")
    public ResponseEntity<String> generateReport(@RequestBody Map<String, String> reportData) {
        try {
            String template = reportData.get("template");
            String shipmentId = reportData.getOrDefault("shipmentId", "");
            String recipientName = reportData.getOrDefault("recipientName", "");
            String origin = reportData.getOrDefault("origin", "");
            String destination = reportData.getOrDefault("destination", "");

            if (template == null || template.trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\": \"Template content is required\"}");
            }

            ResponseEntity<String> response = reportServiceProxy.processTemplate(
                    template, shipmentId, recipientName, origin, destination);
            return ResponseEntity.status(response.getStatusCode())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(response.getBody());
        } catch (Exception e) {
            logger.error("Report generation error: {}", e.getMessage());
            logger.debug("Stack trace:", e);
            return ResponseEntity.status(500)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Report generation failed: " + e.getMessage() + "\"}");
        }
    }

    @GetMapping("/reports/health")
    public ResponseEntity<String> checkReportServiceHealth() {
        try {
            ResponseEntity<String> response = reportServiceProxy.healthCheck();
            return ResponseEntity.status(response.getStatusCode())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(response.getBody());
        } catch (Exception e) {
            logger.error("Report service health check error: {}", e.getMessage());
            logger.debug("Stack trace:", e);
            return ResponseEntity.status(500)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Health check failed: " + e.getMessage() + "\"}");
        }
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception e) {
        logger.error("Exception caught in controller: {} - {}", e.getClass().getSimpleName(), e.getMessage());
        logger.debug("Stack trace:", e);
        return ResponseEntity.status(500)
                .contentType(org.springframework.http.MediaType.TEXT_HTML)
                .body("<div class=\"alert alert-danger\">An error occurred: " + e.getMessage() + "</div>");
    }
}
