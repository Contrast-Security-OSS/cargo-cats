package com.contrast.frontgateservice.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;

@Service
public class TrackingReportServiceProxy {

    @Value("${trackingreportservice.url:http://trackingreportservice:80}")
    private String trackingReportServiceUrl;

    private final RestTemplate restTemplate;

    public TrackingReportServiceProxy() {
        this.restTemplate = new RestTemplate();
    }

    public ResponseEntity<String> getTrackingReport(String trackingId) {
        try {
            String url = trackingReportServiceUrl + "/api/tracking-report?tracking_id="
                    + URLEncoder.encode(trackingId, StandardCharsets.UTF_8);

            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            return restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\": \"Unable to connect to tracking report service\"}");
        }
    }

    public ResponseEntity<String> addTrackingEvent(Map<String, Object> body) {
        try {
            String url = trackingReportServiceUrl + "/api/tracking-report/events";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);

            return restTemplate.exchange(url, HttpMethod.POST, entity, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\": \"Unable to connect to tracking report service\"}");
        }
    }

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

    public ResponseEntity<String> healthCheck() {
        try {
            String url = trackingReportServiceUrl + "/api/health";

            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            return restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\": \"Unable to connect to tracking report service\"}");
        }
    }
}
