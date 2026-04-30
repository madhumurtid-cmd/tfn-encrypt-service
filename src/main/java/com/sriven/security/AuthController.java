package com.sriven.security;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @GetMapping("/token")
    public String getToken() {
        return JwtUtil.generateToken("admin", "RECOVERY");
    }
}