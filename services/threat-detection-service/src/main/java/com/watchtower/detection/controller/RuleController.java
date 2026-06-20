package com.watchtower.detection.controller;

import com.watchtower.detection.entity.DetectionRule;
import com.watchtower.detection.repository.DetectionRuleRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST API for detection rule CRUD.
 */
@RestController
@RequestMapping("/api/v1/rules")
public class RuleController {

    private final DetectionRuleRepository ruleRepository;

    public RuleController(DetectionRuleRepository ruleRepository) {
        this.ruleRepository = ruleRepository;
    }

    @GetMapping
    public List<DetectionRule> getAllRules() {
        return ruleRepository.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<DetectionRule> getRule(@PathVariable Long id) {
        return ruleRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public DetectionRule createRule(@RequestBody DetectionRule rule) {
        return ruleRepository.save(rule);
    }

    @PutMapping("/{id}")
    public ResponseEntity<DetectionRule> updateRule(@PathVariable Long id,
                                                     @RequestBody DetectionRule updated) {
        return ruleRepository.findById(id)
                .map(existing -> {
                    existing.setName(updated.getName());
                    existing.setDescription(updated.getDescription());
                    existing.setRuleType(updated.getRuleType());
                    existing.setSeverity(updated.getSeverity());
                    existing.setConfig(updated.getConfig());
                    existing.setEnabled(updated.isEnabled());
                    return ResponseEntity.ok(ruleRepository.save(existing));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @PatchMapping("/{id}/toggle")
    public ResponseEntity<DetectionRule> toggleRule(@PathVariable Long id) {
        return ruleRepository.findById(id)
                .map(rule -> {
                    rule.setEnabled(!rule.isEnabled());
                    return ResponseEntity.ok(ruleRepository.save(rule));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteRule(@PathVariable Long id) {
        if (ruleRepository.existsById(id)) {
            ruleRepository.deleteById(id);
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.notFound().build();
    }
}
