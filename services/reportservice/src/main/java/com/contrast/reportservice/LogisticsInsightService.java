package com.contrast.reportservice;

import com.openai.client.OpenAIClient;
import com.openai.client.okhttp.OpenAIOkHttpClient;
import com.openai.models.ChatModel;
import com.openai.models.chat.completions.ChatCompletionCreateParams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

/**
 * LogisticsInsightService — silently enriches rendered shipping reports with a
 * one-sentence AI insight using the OpenAI Java SDK pointed at a local Ollama instance.
 *
 * This is the "shadow AI" pattern: the OpenAI SDK is embedded directly inside the
 * report generation service with no dedicated AI service or exposed AI endpoint.
 * Contrast Security agents detect the SDK usage here even though it is hidden inside
 * what looks purely like a report rendering workflow.
 */
public class LogisticsInsightService {

    private static final Logger logger = LoggerFactory.getLogger(LogisticsInsightService.class);

    private final OpenAIClient client;
    private final String modelName;
    private final boolean enabled;

    public LogisticsInsightService() {
        this.enabled = Boolean.parseBoolean(
                System.getenv().getOrDefault("AI_INSIGHTS_ENABLED", "true"));

        if (!enabled) {
            logger.info("LogisticsInsightService disabled via AI_INSIGHTS_ENABLED=false");
            this.client = null;
            this.modelName = null;
            return;
        }

        String baseUrl = System.getenv().getOrDefault("OLLAMA_BASE_URL", "http://ollama:11434/v1");
        this.modelName = System.getenv().getOrDefault("OLLAMA_MODEL", "smollm2:135m");

        this.client = OpenAIOkHttpClient.builder()
                .baseUrl(baseUrl)
                .apiKey("ollama")
                .timeout(Duration.ofSeconds(90))
                .build();

        logger.info("LogisticsInsightService initialized. Base URL: {}, model: {}", baseUrl, modelName);
    }

    /**
     * Generates a brief logistics insight for the given rendered report text.
     * Returns null silently if the AI call fails, so report generation is never blocked.
     */
    public String getInsight(String reportText) {
        if (!enabled) {
            return null;
        }
        try {
            logger.debug("Requesting logistics insight from AI (shadow AI usage)");
            var response = client.chat().completions().create(
                    ChatCompletionCreateParams.builder()
                            .model(ChatModel.of(modelName))
                            .addSystemMessage("You are a logistics analyst. Given a shipping report, provide a single brief operational insight or recommendation in one sentence.")
                            .addUserMessage(reportText)
                            .maxCompletionTokens(80)
                            .build()
            );
            return response.choices().get(0).message().content().orElse(null);
        } catch (Exception e) {
            logger.warn("AI insight generation failed (non-fatal): {}", e.getMessage());
            return null;
        }
    }
}
