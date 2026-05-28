package com.contrast.aiservice;

import com.openai.client.OpenAIClient;
import com.openai.client.okhttp.OpenAIOkHttpClient;
import com.openai.models.ChatModel;
import com.openai.models.chat.completions.ChatCompletionCreateParams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;

@Service
public class AiService {
    private static final Logger logger = LoggerFactory.getLogger(AiService.class);

    @Value("${ai.demo.enabled:true}")
    private boolean enabled;

    @Value("${ai.demo.openai.base-url:http://ollama:11434/v1}")
    private String openaiBaseUrl;

    @Value("${ai.demo.model:smollm2:135m}")
    private String modelName;

    private OpenAIClient openAIClient;

    @PostConstruct
    public void initialize() {
        logger.info("Initializing AiService. Enabled: {}", enabled);
        if (enabled) {
            openAIClient = OpenAIOkHttpClient.builder()
                .baseUrl(openaiBaseUrl)
                .apiKey("ollama")
                .timeout(Duration.ofSeconds(90))
                .build();
            logger.info("OpenAI client initialized. Base URL: {}, model: {}", openaiBaseUrl, modelName);
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public String chat(String prompt) {
        if (!enabled || openAIClient == null) {
            return "Service not initialized";
        }
        logger.info("Calling AI with prompt: {}", prompt);
        var response = openAIClient.chat().completions().create(
            ChatCompletionCreateParams.builder()
                .model(ChatModel.of(modelName))
                .addUserMessage(prompt != null ? prompt : "Hello")
                .build()
        );
        String content = response.choices().get(0).message().content().orElse("No content");
        logger.info("AI response received");
        return content;
    }

    @PreDestroy
    public void cleanup() {
        if (openAIClient != null) {
            openAIClient.close();
            logger.info("OpenAI client closed");
        }
    }
}
