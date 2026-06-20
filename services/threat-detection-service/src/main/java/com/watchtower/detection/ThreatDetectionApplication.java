package com.watchtower.detection;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class ThreatDetectionApplication {

    public static void main(String[] args) {
        SpringApplication.run(ThreatDetectionApplication.class, args);
    }
}
