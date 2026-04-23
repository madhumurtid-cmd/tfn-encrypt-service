package com.sriven.encrypt;

import org.springframework.web.bind.annotation.*;
import java.util.*;

import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.charset.StandardCharsets;

@RestController
public class EncryptController {

    // =========================
    // 🔐 ENCRYPT ENDPOINT
    // =========================
    @PostMapping("/encrypt")
    public Map<String, Object> encrypt(@RequestBody Map<String, Object> input) {

        String key = getKey();

        Map<String, Object> output = new HashMap<>();

        output.put("TFN", processTFN((String) input.get("TFN"), key, true));
        output.put("TFN_SECONDARY", processTFN((String) input.get("TFN_SECONDARY"), key, true));
        output.put("TFN_TERTIARY", processTFN((String) input.get("TFN_TERTIARY"), key, true));

        output.put("ENCRYPTED_FLAG", "Y");

        return output;
    }

    // =========================
    // 🔓 DECRYPT ENDPOINT
    // =========================
    @PostMapping("/decrypt")
    public Map<String, Object> decrypt(@RequestBody Map<String, Object> input) {

        String key = getKey();

        Map<String, Object> output = new HashMap<>();

        output.put("TFN", processTFN((String) input.get("TFN"), key, false));
        output.put("TFN_SECONDARY", processTFN((String) input.get("TFN_SECONDARY"), key, false));
        output.put("TFN_TERTIARY", processTFN((String) input.get("TFN_TERTIARY"), key, false));

        output.put("DECRYPTED_FLAG", "Y");

        return output;
    }

    // =========================
    // 🔁 CORE FF1 LOGIC
    // =========================
    private String processTFN(String tfn, String keyStr, boolean encryptMode) {

        if (tfn == null || tfn.trim().isEmpty()) {
            return null;
        }

        try {
            // Remove dashes
            String digits = tfn.replace("-", "");

            // Validate numeric
            if (!digits.matches("\\d+")) {
                throw new RuntimeException("Invalid TFN: " + tfn);
            }

            // Convert digits → byte[]
            byte[] input = new byte[digits.length()];
            for (int i = 0; i < digits.length(); i++) {
                input[i] = (byte) (digits.charAt(i) - '0');
            }

            // Key (16 bytes)
            byte[] key = Arrays.copyOf(keyStr.getBytes(StandardCharsets.UTF_8), 16);

            // 🔥 FIXED: use EMPTY tweak (NOT null)
            FPEParameters params = new FPEParameters(
                    new KeyParameter(key),
                    10,
                    new byte[0]
            );

            FPEFF1Engine engine = new FPEFF1Engine();
            engine.init(encryptMode, params);

            byte[] output = new byte[input.length];

            engine.processBlock(input, 0, input.length, output, 0);

            // Convert back safely
            StringBuilder result = new StringBuilder();
            for (byte b : output) {
                int digit = b & 0xFF;   // 🔥 ensure positive
                digit = digit % 10;     // 🔥 ensure 0–9
                result.append(digit);
            }

            String formatted = result.toString();

            if (formatted.length() != 10) {
                throw new RuntimeException("Invalid output length: " + formatted);
            }

            // Format back to TFN
            return formatted.substring(0, 4) + "-" +
                   formatted.substring(4, 8) + "-" +
                   formatted.substring(8, 10);

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("TFN processing failed: " + tfn, e);
        }
    }

    // =========================
    // 🔑 ENV KEY
    // =========================
    private String getKey() {
        String key = System.getenv("TFN_KEY");
        if (key == null || key.isEmpty()) {
            throw new RuntimeException("TFN_KEY not set in environment");
        }
        return key;
    }
}