package com.watchtower.fim;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class FileIntegrityApplication {
    public static void main(String[] args) {
        SpringApplication.run(FileIntegrityApplication.class, args);
    }
}
