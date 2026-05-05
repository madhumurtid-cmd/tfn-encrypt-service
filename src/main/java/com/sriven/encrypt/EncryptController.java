package com.sriven.encrypt;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import org.springframework.boot.web.client.RestTemplateBuilder;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.Authentication;

import java.util.*;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;

@RestController
@RequestMapping("/crypto")
public class EncryptController {

    private final RestTemplate restTemplate;
    private final String KMS_URL = "http://localhost:8081";

    public EncryptController(RestTemplateBuilder builder) {
        this.restTemplate = builder
                .setConnectTimeout(Duration.ofSeconds(3))
                .setReadTimeout(Duration.ofSeconds(3))
                .build();
    }

    // =========================
    // ENCRYPT
    // =========================
    @PostMapping("/encrypt")
    public Map<String, Object> encrypt(@RequestBody Map<String, Object> input) {

        String keyId = extractString(input.get("keyId"), "keyId");
        validateForEncryption(input);

        String key = fetchKeyFromKMS(keyId);

        return processAll(input, key, true);
    }

    // =========================
    // DECRYPT
    // =========================
    @PostMapping("/decrypt")
    public Map<String, Object> decrypt(@RequestBody Map<String, Object> input) {

        String keyId = extractString(input.get("keyId"), "keyId");
        String key = fetchKeyFromKMS(keyId);

        boolean recovery = Boolean.TRUE.equals(input.get("recovery"));

        if (recovery) {
            validateRecoveryAccess();
        } else {
            validateEncryptedInputs(input, key);
        }

        return processAll(input, key, false);
    }

    // =========================
    // VALIDATION
    // =========================
    private void validateForEncryption(Map<String, Object> input) {

        Object flag = input.get("shouldEncrypt");

        boolean shouldEncrypt =
                (flag instanceof Boolean && (Boolean) flag) ||
                (flag instanceof String && Boolean.parseBoolean((String) flag));

        if (!shouldEncrypt) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Encryption not allowed"
            );
        }
    }

    private void validateEncryptedInputs(Map<String, Object> input, String key) {
        checkField(input.get("TFN"), key, "TFN");
        checkField(input.get("TFN_SECONDARY"), key, "TFN_SECONDARY");
        checkField(input.get("TFN_TERTIARY"), key, "TFN_TERTIARY");
    }

    private void checkField(Object valueObj, String key, String fieldName) {
        if (valueObj == null) return;

        String value = valueObj.toString();

        if (!isAlreadyEncrypted(value, key)) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    fieldName + " is not encrypted"
            );
        }
    }

    // =========================
    // KMS CALL (with timeout safety)
    // =========================
    private String fetchKeyFromKMS(String keyId) {

        if (keyId == null || keyId.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing keyId");
        }

        try {
            return restTemplate.getForObject(
                    KMS_URL + "/key/decrypt?keyId=" + keyId,
                    String.class
            );
        } catch (Exception e) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY,
                    "KMS unavailable"
            );
        }
    }

    // =========================
    // CORE PROCESSING
    // =========================
    private Map<String, Object> processAll(Map<String, Object> input,
                                           String key,
                                           boolean encryptMode) {

        Map<String, Object> output = new HashMap<>();

        output.put("TFN", processTFN(extractString(input.get("TFN"), "TFN"), key, encryptMode));
        output.put("TFN_SECONDARY", processTFN(extractString(input.get("TFN_SECONDARY"), "TFN_SECONDARY"), key, encryptMode));
        output.put("TFN_TERTIARY", processTFN(extractString(input.get("TFN_TERTIARY"), "TFN_TERTIARY"), key, encryptMode));

        output.put("ENCRYPTED_FLAG", encryptMode ? "Y" : "N");

        return output;
    }

    // =========================
    // SAFE STRING EXTRACTION
    // =========================
    private String extractString(Object obj, String fieldName) {

        if (obj == null) return null;

        if (obj instanceof String) return (String) obj;

        if (obj instanceof Map) {
            Object val = ((Map<?, ?>) obj).get("value");
            if (val != null) return val.toString();
        }

        throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Invalid format for " + fieldName
        );
    }

    // =========================
    // THREAD-SAFE FPE (CRITICAL FIX)
    // =========================
    private String processTFN(String tfn, String keyStr, boolean encryptMode) {

        if (tfn == null || tfn.isBlank()) return null;

        try {
            String digits = tfn.replace("-", "");

            if (!digits.matches("\\d{10}")) {
                throw new ResponseStatusException(
                        HttpStatus.BAD_REQUEST,
                        "Invalid TFN format"
                );
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

            // 🔥 CRITICAL: new engine per call (thread-safe)
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
            throw new ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    "TFN processing failed"
            );
        }
    }

    private byte[] deriveKey(String keyStr) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return Arrays.copyOf(
                digest.digest(keyStr.getBytes(StandardCharsets.UTF_8)),
                16
        );
    }

    // =========================
    // SECURITY
    // =========================
    private void validateRecoveryAccess() {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || auth.getAuthorities().stream()
                .noneMatch(a -> a.getAuthority().equals("ROLE_RECOVERY"))) {

            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "Recovery requires ROLE_RECOVERY"
            );
        }
    }

    private boolean isAlreadyEncrypted(String value, String key) {
        try {
            String decrypted = processTFN(value, key, false);
            String reEncrypted = processTFN(decrypted, key, true);
            return value.equals(reEncrypted);
        } catch (Exception e) {
            return false;
        }
    }
}