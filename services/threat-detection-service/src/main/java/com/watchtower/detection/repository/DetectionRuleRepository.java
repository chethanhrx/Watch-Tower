package com.watchtower.detection.repository;

import com.watchtower.common.enums.RuleType;
import com.watchtower.detection.entity.DetectionRule;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface DetectionRuleRepository extends JpaRepository<DetectionRule, Long> {
    List<DetectionRule> findByEnabledTrue();
    List<DetectionRule> findByRuleTypeAndEnabledTrue(RuleType ruleType);
}
