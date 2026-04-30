package com.sriven.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        System.out.println("🔥 CUSTOM SECURITY CONFIG ACTIVE");

        http
            .csrf(csrf -> csrf.disable())

            // 🔥 THIS IS THE KEY LINE
            .securityMatcher("/**")

            .authorizeHttpRequests(auth -> auth
                .anyRequest().permitAll()   // 🔥 allow everything (test phase)
            )

            // 🔥 remove ALL default login mechanisms
            .formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable())
            .logout(logout -> logout.disable());

        return http.build();
    }
}