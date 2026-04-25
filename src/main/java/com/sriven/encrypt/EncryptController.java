package com.sriven.encrypt;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.*;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;

@RestController
@RequestMapping("/crypto")
public class EncryptController {

    private final RestTemplate restTemplate = new RestTemplate();
    private final String KMS_URL = "http://localhost:8081";

    // =========================
    // ENCRYPT
    // =========================
    @PostMapping("/encrypt")
    public Map<String, Object> encrypt(@RequestBody Map<String, Object> input) {

        validateNotAlreadyEncrypted(input);

        String keyId = (String) input.get("keyId");
        String key = fetchKeyFromKMS(keyId);

        return processAll(input, key, true);
    }

    // =========================
    // DECRYPT
    // =========================
    @PostMapping("/decrypt")
    public Map<String, Object> decrypt(@RequestBody Map<String, Object> input) {

        validateIsEncrypted(input);

        String keyId = (String) input.get("keyId");
        String key = fetchKeyFromKMS(keyId);

        return processAll(input, key, false);
    }

    // =========================
    // VALIDATIONS (NEW)
    // =========================
    private void validateNotAlreadyEncrypted(Map<String, Object> input) {

        Object flag = input.get("ENCRYPTED_FLAG");

        if ("Y".equalsIgnoreCase(String.valueOf(flag))) {
            throw new IllegalStateException(
                "Payload is already encrypted. Double encryption is not allowed."
            );
        }
    }

    private void validateIsEncrypted(Map<String, Object> input) {

        Object flag = input.get("ENCRYPTED_FLAG");

        if (!"Y".equalsIgnoreCase(String.valueOf(flag))) {
            throw new IllegalStateException(
                "Payload is not encrypted. Cannot decrypt."
            );
        }
    }

    // =========================
    // SHARED LOGIC
    // =========================
    private Map<String, Object> processAll(Map<String, Object> input, String key, boolean encryptMode) {

        Map<String, Object> output = new HashMap<>();

        output.put("TFN", processTFN((String) input.get("TFN"), key, encryptMode));
        output.put("TFN_SECONDARY", processTFN((String) input.get("TFN_SECONDARY"), key, encryptMode));
        output.put("TFN_TERTIARY", processTFN((String) input.get("TFN_TERTIARY"), key, encryptMode));

        output.put("ENCRYPTED_FLAG", encryptMode ? "Y" : "N");

        return output;
    }

    // =========================
    // KMS CALL
    // =========================
    private String fetchKeyFromKMS(String keyId) {

        if (keyId == null || keyId.isBlank()) {
            throw new IllegalArgumentException("keyId is required");
        }

        return restTemplate.getForObject(
                KMS_URL + "/key/decrypt?keyId=" + keyId,
                String.class
        );
    }

    // =========================
    // FF1 PROCESSING
    // =========================
    private String processTFN(String tfn, String keyStr, boolean encryptMode) {

        if (tfn == null || tfn.trim().isEmpty()) return null;

        try {
            String digits = tfn.replace("-", "");

            if (!digits.matches("\\d{10}")) {
                throw new IllegalArgumentException("Invalid TFN format");
            }

            byte[] input = new byte[digits.length()];
            for (int i = 0; i < digits.length(); i++) {
                input[i] = (byte) (digits.charAt(i) - '0');
            }

            byte[] key = deriveKey(keyStr);

            FPEParameters params = new FPEParameters(
                    new KeyParameter(key),
                    10,
                    new byte[0]
            );

            FPEFF1Engine engine = new FPEFF1Engine();
            engine.init(encryptMode, params);

            byte[] output = new byte[input.length];
            engine.processBlock(input, 0, input.length, output, 0);

            StringBuilder result = new StringBuilder();
            for (byte b : output) {
                result.append((int) b);
            }

            String formatted = result.toString();

            return formatted.substring(0, 4) + "-" +
                   formatted.substring(4, 8) + "-" +
                   formatted.substring(8, 10);

        } catch (Exception e) {
            throw new RuntimeException("TFN processing failed", e);
        }
    }

    // =========================
    // KEY DERIVATION
    // =========================
    private byte[] deriveKey(String keyStr) throws Exception {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        return Arrays.copyOf(
                digest.digest(keyStr.getBytes(StandardCharsets.UTF_8)),
                16
        );
    }
}