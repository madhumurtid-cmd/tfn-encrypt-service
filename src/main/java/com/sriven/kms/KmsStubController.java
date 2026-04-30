package com.sriven.kms;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/key")
public class KmsStubController {

    @GetMapping("/decrypt")
    public String decrypt(@RequestParam String keyId) {

        System.out.println("🔑 KMS STUB CALLED with keyId=" + keyId);

        if (keyId == null || keyId.isBlank()) {
            throw new RuntimeException("keyId missing");
        }

        // return fake key
        return "stub-secret-" + keyId;
    }
}