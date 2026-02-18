package com.contrast.frontgateservice.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

@Service
public class ReportServiceProxy {

    @Value("${reportservice.url:http://reportservice:8080}")
    private String reportServiceUrl;

    private final RestTemplate restTemplate;

    public ReportServiceProxy() {
        this.restTemplate = new RestTemplate();
    }

    /**
     * Process a report template by sending it to the report service.
     * The report service uses FreeMarker to render the template with the provided variables.
     */
    public ResponseEntity<String> processTemplate(String template, String shipmentId,
                                                    String recipientName, String origin,
                                                    String destination) {
        try {
            String url = reportServiceUrl + "/template";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("template", template);
            body.add("shipmentId", shipmentId);
            body.add("recipientName", recipientName);
            body.add("origin", origin);
            body.add("destination", destination);

            HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(body, headers);

            return restTemplate.exchange(url, HttpMethod.POST, requestEntity, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\": \"Report service unavailable: " + e.getMessage() + "\"}");
        }
    }

    /**
     * Health check for the report service.
     */
    public ResponseEntity<String> healthCheck() {
        try {
            String url = reportServiceUrl + "/health";

            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(java.util.Collections.singletonList(MediaType.APPLICATION_JSON));

            HttpEntity<String> entity = new HttpEntity<>(headers);

            return restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\": \"Report service health check failed: " + e.getMessage() + "\"}");
        }
    }
}
