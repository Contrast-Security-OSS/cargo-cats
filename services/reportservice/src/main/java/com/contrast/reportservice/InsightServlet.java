package com.contrast.reportservice;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(name = "InsightServlet", urlPatterns = {"/insight"})
public class InsightServlet extends HttpServlet {

    private LogisticsInsightService insightService;

    @Override
    public void init() throws ServletException {
        super.init();
        insightService = new LogisticsInsightService();
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String reportText = request.getParameter("reportText");

        response.setContentType("application/json");

        if (reportText == null || reportText.trim().isEmpty()) {
            response.setStatus(400);
            response.getWriter().write("{\"error\": \"reportText is required\"}");
            return;
        }

        try {
            String insight = insightService.getInsight(reportText);
            if (insight != null && !insight.isBlank()) {
                response.getWriter().write("{\"success\": true, \"logistics_insight\": " + escapeJsonString(insight) + "}");
            } else {
                response.getWriter().write("{\"success\": true, \"logistics_insight\": null}");
            }
        } catch (Exception e) {
            response.setStatus(500);
            response.getWriter().write("{\"error\": " + escapeJsonString("Insight generation failed: " + e.getMessage()) + "}");
        }
    }

    private String escapeJsonString(String text) {
        if (text == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (char c : text.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }
}
