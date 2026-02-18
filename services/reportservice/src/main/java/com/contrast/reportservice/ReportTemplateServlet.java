package com.contrast.reportservice;

import fr.opensagres.xdocreport.template.IContext;
import fr.opensagres.xdocreport.template.freemarker.FreemarkerTemplateEngine;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

/**
 * ReportTemplateServlet - Processes shipping report templates using FreeMarker.
 * 
 * VULNERABLE: Uses XDocReport FreeMarker template engine v2.1.0 which is
 * susceptible to Server-Side Template Injection (SSTI) via CVE-2025-66474.
 * 
 * The vulnerability allows attackers to inject malicious FreeMarker directives
 * that can instantiate arbitrary Java classes and execute system commands.
 */
@WebServlet(name = "ReportTemplateServlet", urlPatterns = {"/template"})
public class ReportTemplateServlet extends HttpServlet {
    
    private FreemarkerTemplateEngine templateEngine;
    
    @Override
    public void init() throws ServletException {
        super.init();
        templateEngine = new FreemarkerTemplateEngine();
    }
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("application/json");
        response.getWriter().write("{\"status\":\"ok\",\"service\":\"reportservice\",\"endpoint\":\"/template\"}");
    }
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        String template = request.getParameter("template");
        String shipmentId = request.getParameter("shipmentId");
        String recipientName = request.getParameter("recipientName");
        String origin = request.getParameter("origin");
        String destination = request.getParameter("destination");
        
        if (template == null || template.trim().isEmpty()) {
            response.setContentType("application/json");
            response.setStatus(400);
            response.getWriter().write("{\"error\": \"Template content is required\"}");
            return;
        }
        
        if (shipmentId == null || shipmentId.trim().isEmpty()) shipmentId = "N/A";
        if (recipientName == null || recipientName.trim().isEmpty()) recipientName = "N/A";
        if (origin == null || origin.trim().isEmpty()) origin = "N/A";
        if (destination == null || destination.trim().isEmpty()) destination = "N/A";
        
        response.setContentType("application/json");
        
        try {
            // VULNERABLE: Directly processing user-provided template content
            // The FreeMarker ?new operator allows instantiation of arbitrary Java classes
            StringReader reader = new StringReader(template);
            StringWriter writer = new StringWriter();
            IContext context = templateEngine.createContext();
            context.put("shipmentId", shipmentId);
            context.put("recipientName", recipientName);
            context.put("origin", origin);
            context.put("destination", destination);
            context.put("date", java.time.LocalDate.now().toString());
            context.put("company", "Global Shipping Co.");
            
            templateEngine.process("report-template", context, reader, writer);
            
            String result = writer.toString();
            
            // Return JSON response
            String jsonResult = "{\"success\": true, \"output\": " + escapeJsonString(result) + "}";
            response.getWriter().write(jsonResult);
            
        } catch (Exception e) {
            response.setStatus(500);
            response.getWriter().write("{\"error\": " + escapeJsonString("Template processing failed: " + e.getMessage()) + "}");
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
