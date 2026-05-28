package com.contrast.frontgateservice.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

@Service
public class AiServiceProxy {

    @Value("${aiservice.url:http://aiservice:8080}")
    private String aiServiceUrl;

    private final RestTemplate restTemplate;

    public AiServiceProxy() {
        this.restTemplate = new RestTemplate();
    }

    /**
     * Health check for AI service
     */
    public ResponseEntity<String> healthCheck() {
        try {
            String url = aiServiceUrl + "/api/ai/health";
            return restTemplate.exchange(url, HttpMethod.GET, null, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error: " + e.getMessage());
        }
    }

    /**
     * Call OpenAI API endpoint
     */
    public ResponseEntity<String> openai(String prompt) {
        try {
            String url = aiServiceUrl + "/api/ai/openai";
            if (prompt != null && !prompt.isEmpty()) {
                url += "?prompt=" + org.springframework.web.util.UriUtils.encodeQueryParam(prompt, "UTF-8");
            }
            return restTemplate.exchange(url, HttpMethod.GET, null, String.class);
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error: " + e.getMessage());
        }
    }
}
