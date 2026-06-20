package com.watchtower.ingestion;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class LogIngestionApplication {

    public static void main(String[] args) {
        SpringApplication.run(LogIngestionApplication.class, args);
    }
}
