package com.contrast.frontgateservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @SuppressWarnings("deprecation") // Intentionally using deprecated MD5 for educational demo
    public PasswordEncoder passwordEncoder() {
        // INSECURE: Using MD5 for educational purposes to demonstrate weak password storage
        // MD5 is cryptographically broken and should NEVER be used in production
        return new MessageDigestPasswordEncoder("MD5");
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeRequests(authz -> authz
                .antMatchers("/", "/css/**", "/js/**", "/images/**", "/register", "/login").permitAll()
                .antMatchers(HttpMethod.GET, "/api/shipments/track/**").permitAll() // Allow public shipment tracking
                .antMatchers(HttpMethod.DELETE, "/api/cats/**").permitAll() //oops, probs shoundn't allow everyone to delete
                .antMatchers("/api/ai/**").permitAll() // Public so the AI usage demo can be triggered with curl
                .antMatchers("/api/**").authenticated()
                .anyRequest().authenticated()
            )
            .csrf(csrf -> csrf.disable()) // Disable CSRF protection entirely
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error=true")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutSuccessUrl("/login?logout=true")
                .permitAll()
            );

        return http.build();
    }
}
