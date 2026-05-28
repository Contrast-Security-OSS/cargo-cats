package com.contrast.aiservice;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin(originPatterns = "*")
public class AiController {
    private static final Logger logger = LoggerFactory.getLogger(AiController.class);

    @Autowired
    private AiService aiService;

    @GetMapping("/api/ai/health")
    public ResponseEntity<String> health() {
        if (aiService.isEnabled()) {
            return ResponseEntity.ok("AI Service is operational");
        }
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body("AI Service is not available");
    }

    @GetMapping("/api/ai/openai")
    public ResponseEntity<String> openai(@RequestParam(value = "prompt", required = false) String prompt) {
        try {
            logger.info("OpenAI endpoint called with prompt: {}", prompt);
            return ResponseEntity.ok(aiService.chat(prompt));
        } catch (Exception e) {
            logger.error("Error in openai endpoint", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error: " + e.getMessage());
        }
    }
}
