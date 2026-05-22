package com.contrast.frontgateservice.service;

import com.anthropic.client.AnthropicClient;
import com.anthropic.client.okhttp.AnthropicOkHttpClient;
import com.anthropic.errors.AnthropicException;
import com.anthropic.models.messages.ContentBlock;
import com.anthropic.models.messages.Message;
import com.anthropic.models.messages.MessageCreateParams;
import com.anthropic.models.messages.Model;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import javax.annotation.PostConstruct;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

/**
 * Calls the Anthropic Messages API through the official Anthropic Java SDK. The Contrast Java agent
 * instruments {@code com.anthropic.services.blocking.MessageServiceImpl}, so calls made through
 * this client surface as ai_usage events in Explorer. A raw {@code RestTemplate} POST to the same
 * URL would NOT be detected, the sensor matches on SDK class names, not on outbound host.
 *
 * The call does not need to succeed for detection to fire: a dummy API key produces a 401 from
 * Anthropic, but the SDK invocation still runs through the instrumented code path and the agent
 * still records it.
 */
@Service
public class AiAssistantProxy {

    private static final Logger logger = LogManager.getLogger(AiAssistantProxy.class);

    @Value("${anthropic.api-key:${ANTHROPIC_API_KEY:sk-ant-test-placeholder}}")
    private String anthropicApiKey;

    @Value("${anthropic.model:claude-haiku-4-5}")
    private String anthropicModel;

    @Value("${anthropic.base-url:https://api.anthropic.com}")
    private String anthropicBaseUrl;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private AnthropicClient client;

    @PostConstruct
    void init() {
        this.client = AnthropicOkHttpClient.builder()
                .apiKey(anthropicApiKey)
                .baseUrl(anthropicBaseUrl)
                .build();
    }

    public ResponseEntity<String> ask(String prompt) {
        try {
            logger.info("Calling Anthropic Messages API via SDK: model={}", anthropicModel);
            MessageCreateParams params = MessageCreateParams.builder()
                    .model(anthropicModel)
                    .maxTokens(128L)
                    .addUserMessage(prompt)
                    .build();

            Message message = client.messages().create(params);

            ObjectNode result = objectMapper.createObjectNode();
            result.put("id", message.id());
            result.put("model", message.model().toString());
            ArrayNode content = result.putArray("content");
            for (ContentBlock block : message.content()) {
                block.text().ifPresent(t -> content.add(t.text()));
            }
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(objectMapper.writeValueAsString(result));
        } catch (AnthropicException e) {
            logger.warn("Anthropic SDK error: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Anthropic SDK error: " + escape(e.getMessage()) + "\"}");
        } catch (Exception e) {
            logger.error("Failed to call Anthropic", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"Failed to call AI assistant: " + escape(e.getMessage()) + "\"}");
        }
    }

    private static String escape(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
