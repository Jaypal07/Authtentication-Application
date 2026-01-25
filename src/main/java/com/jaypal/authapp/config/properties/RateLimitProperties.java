package com.jaypal.authapp.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
@ConfigurationProperties(prefix = "rate-limit")
public class RateLimitProperties {

    private List<String> internalCidrs = new ArrayList<>();

    private Map<String, Limit> endpoints = new HashMap<>();

    private Limit loginEmail = new Limit(10, 1);
    private Limit loginIp = new Limit(50, 5);
    private Limit invalidRefresh = new Limit(10, 1);
    private Limit refreshRotate = new Limit(5, 1);

    @Data
    public static class Limit {
        private int capacity = 100;
        private int refillPerSecond = 1;

        public Limit() {}

        public Limit(int capacity, int refillPerSecond) {
            this.capacity = capacity;
            this.refillPerSecond = refillPerSecond;
        }
    }
}

