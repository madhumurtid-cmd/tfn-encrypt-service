package com.sriven.encrypt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.sriven")
public class EncryptApplication {
    public static void main(String[] args) {
        SpringApplication.run(EncryptApplication.class, args);
    }
}