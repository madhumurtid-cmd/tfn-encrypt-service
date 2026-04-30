package com.sriven.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.List;

@Component
public class JwtFilter extends OncePerRequestFilter {

    // ✅ Skip JWT filter for auth endpoints
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/auth/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain filterChain)
            throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {

            String token = header.substring(7);

            try {
                io.jsonwebtoken.Claims claims = JwtUtil.validateToken(token);

                String role = claims.get("role", String.class);

                List<GrantedAuthority> authorities =
                        List.of(new SimpleGrantedAuthority("ROLE_" + role));

                Authentication auth = new UsernamePasswordAuthenticationToken(
                        claims.getSubject(), null, authorities);

                SecurityContextHolder.getContext().setAuthentication(auth);

                System.out.println("ROLE FROM TOKEN: " + role);
                System.out.println("AUTHORITIES: " + authorities);

            } catch (Exception e) {
                // ✅ FIX: do NOT block request
                System.out.println("JWT validation failed: " + e.getMessage());

                // clear context just in case
                SecurityContextHolder.clearContext();
            }
        }

        // ✅ ALWAYS continue
        filterChain.doFilter(request, response);
    }
}