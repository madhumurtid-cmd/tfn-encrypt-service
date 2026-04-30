package com.sriven.encrypt;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.Authentication;

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
    // DEBUG (optional)
    // =========================
    @GetMapping("/debug/auth")
    public String debugAuth() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "AUTH=" + auth.getAuthorities();
    }

    // =========================
    // ENCRYPT
    // =========================
    @PostMapping("/encrypt")
    public Map<String, Object> encrypt(@RequestBody Map<String, Object> input) {

        String keyId = (String) input.get("keyId");
        String key = fetchKeyFromKMS(keyId);
        System.out.println("🔥 HIT ENCRYPT ENDPOINT");
        validateForEncryption(input);

        return processAll(input, key, true);
    }

    // =========================
    // DECRYPT
    // =========================
    @PostMapping("/decrypt")
    public Map<String, Object> decrypt(@RequestBody Map<String, Object> input) {

        String keyId = (String) input.get("keyId");
        String key = fetchKeyFromKMS(keyId);

        boolean recovery = Boolean.TRUE.equals(input.get("recovery"));

        if (recovery) {
            validateRecoveryAccess(); // 🔐 only here we enforce role
        } else {
            validateEncryptedInputs(input, key); // fail-fast
        }

        return processAll(input, key, false);
    }

    // =========================
    // DRY RUN
    // =========================
    @PostMapping("/decrypt/dry-run")
    public Map<String, Object> dryRun(@RequestBody Map<String, Object> input) {

        String keyId = (String) input.get("keyId");
        String key = fetchKeyFromKMS(keyId);

        List<Map<String, Object>> results = new ArrayList<>();

        processDryRunField(results, "TFN", (String) input.get("TFN"), key);
        processDryRunField(results, "TFN_SECONDARY", (String) input.get("TFN_SECONDARY"), key);
        processDryRunField(results, "TFN_TERTIARY", (String) input.get("TFN_TERTIARY"), key);

        return Map.of(
                "results", results,
                "summary", generateSummary(results)
        );
    }

    // =========================
    // DRY RUN HELPERS
    // =========================
    private void processDryRunField(List<Map<String, Object>> results,
                                   String field,
                                   String value,
                                   String key) {

        if (value == null) return;

        boolean encrypted = isAlreadyEncrypted(value, key);

        String proposed = processTFN(value, key, false);

        String action = encrypted ? "DECRYPT" : "SKIP";

        results.add(Map.of(
                "field", field,
                "input", value,
                "looksEncrypted", encrypted,
                "proposedOutput", proposed,
                "action", action
        ));
    }

    private Map<String, Object> generateSummary(List<Map<String, Object>> results) {

        long decrypt = results.stream()
                .filter(r -> r.get("action").equals("DECRYPT"))
                .count();

        long skip = results.stream()
                .filter(r -> r.get("action").equals("SKIP"))
                .count();

        return Map.of(
                "total", results.size(),
                "decryptCount", decrypt,
                "skipCount", skip
        );
    }

    // =========================
    // VALIDATION
    // =========================
    private void validateForEncryption(Map<String, Object> input) {

    Object flag = input.get("shouldEncrypt");  // ✅ define it

    Boolean shouldEncrypt = false;

    if (flag instanceof Boolean) {
        shouldEncrypt = (Boolean) flag;
    } else if (flag instanceof String) {
        shouldEncrypt = Boolean.parseBoolean((String) flag);
    }

    if (!Boolean.TRUE.equals(shouldEncrypt)) {
        throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Encryption not allowed (false positive prevention)"
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
                    fieldName + " is not encrypted. Aborting decrypt."
            );
        }
    }

    // =========================
    // RECOVERY SECURITY
    // =========================
    private void validateRecoveryAccess() {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || auth.getAuthorities().stream()
                .noneMatch(a -> a.getAuthority().equals("ROLE_RECOVERY"))) {

            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "Recovery mode requires RECOVERY role"
            );
        }
    }

    // =========================
    // DETECTION
    // =========================
    private boolean isAlreadyEncrypted(String value, String key) {

        try {
            String decrypted = processTFN(value, key, false);
            String reEncrypted = processTFN(decrypted, key, true);

            return value.equals(reEncrypted);

        } catch (Exception e) {
            return false;
        }
    }

    // =========================
    // CORE PROCESSING
    // =========================
    private Map<String, Object> processAll(Map<String, Object> input,
                                           String key,
                                           boolean encryptMode) {

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

    try {
        return restTemplate.getForObject(
            KMS_URL + "/key/decrypt?keyId=" + keyId,
            String.class
        );
    } catch (Exception e) {
        throw new ResponseStatusException(
            HttpStatus.BAD_GATEWAY,
            "KMS service unavailable"
        );
    }
}

    // =========================
    // FPE
    // =========================
    private String processTFN(String tfn, String keyStr, boolean encryptMode) {

        if (tfn == null || tfn.trim().isEmpty()) return null;

        try {
            String digits = tfn.replace("-", "");

            if (!digits.matches("\\d{10}")) {
                throw new ResponseStatusException(
                        HttpStatus.BAD_REQUEST,
                        "Invalid TFN format: " + tfn
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

        } catch (ResponseStatusException e) {
            throw e;
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
}