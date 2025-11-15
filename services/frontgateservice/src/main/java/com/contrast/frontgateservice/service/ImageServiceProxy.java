package com.contrast.frontgateservice.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.multipart.MultipartFile;

import java.util.Collections;

@Service
public class ImageServiceProxy {

    @Value("${imageservice.url:http://imageservice:5001}")
    private String imageServiceUrl;

    private final RestTemplate restTemplate;

    public ImageServiceProxy() {
        this.restTemplate = new RestTemplate();
    }

    public ResponseEntity<String> getPhotos() {
        try {
            String url = imageServiceUrl + "/";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
            
            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
            
            return response;
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\": \"Failed to communicate with image service: " + e.getMessage() + "\"}");
        }
    }

    public ResponseEntity<String> savePhoto(MultipartFile file) {
        try {
            String url = imageServiceUrl + "/savephoto";
            System.out.println("DEBUG: Attempting to upload photo to: " + url);
            System.out.println("DEBUG: File name: " + file.getOriginalFilename());
            System.out.println("DEBUG: File size: " + file.getSize());
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);
            
            MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
            
            // Convert MultipartFile to ByteArrayResource for RestTemplate
            ByteArrayResource fileResource = new ByteArrayResource(file.getBytes()) {
                @Override
                public String getFilename() {
                    return file.getOriginalFilename();
                }
            };
            
            body.add("file", fileResource);
            
            HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);
            
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, requestEntity, String.class);
            
            System.out.println("DEBUG: Image service response status: " + response.getStatusCode());
            System.out.println("DEBUG: Image service response body: " + response.getBody());
            
            return response;
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            System.err.println("DEBUG: HTTP error uploading photo: " + e.getStatusCode() + " - " + e.getMessage());
            System.err.println("DEBUG: Response body: " + e.getResponseBodyAsString());
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        } catch (Exception e) {
            System.err.println("DEBUG: Exception uploading photo: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\": \"Failed to upload photo: " + e.getMessage() + "\"}");
        }
    }

    public ResponseEntity<byte[]> getPhoto(String path) {
        try {
            String url = imageServiceUrl + "/getphoto?path=" + path;
            
            HttpHeaders headers = new HttpHeaders();
            
            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            ResponseEntity<byte[]> response = restTemplate.exchange(url, HttpMethod.GET, entity, byte[].class);
            
            return response;
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(null);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }
}
