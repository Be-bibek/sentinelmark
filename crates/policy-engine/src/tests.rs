#[cfg(test)]
mod tests {
    use crate::{PolicyEngine, Policy, RuleGroup, Rule, Condition, Operator, PolicyDecision};
    use context_engine::EventContext;
    use trust_engine::TrustScore;
    use uuid::Uuid;
    use std::collections::HashMap;
    use serde_json::json;

    #[test]
    fn test_ast_evaluation_and_priority() {
        let condition_high_risk = Condition::Expression {
            operator: Operator::GreaterThan,
            field: "trust.risk_score".to_string(),
            value: json!(0.8),
        };

        let condition_country = Condition::Expression {
            operator: Operator::In,
            field: "context.country".to_string(),
            value: json!(["RU", "KP"]),
        };

        let rule_1 = Rule {
            id: "block_high_risk_geo".to_string(),
            name: "Block High Risk Geo".to_string(),
            description: None,
            priority: 100,
            enabled: true,
            continue_processing: false,
            condition: Condition::And {
                and: vec![condition_high_risk, condition_country],
            },
            action: PolicyDecision::Block,
        };

        let rule_2 = Rule {
            id: "fallback_allow".to_string(),
            name: "Fallback Allow".to_string(),
            description: None,
            priority: 10,
            enabled: true,
            continue_processing: false,
            condition: Condition::Expression {
                operator: Operator::GreaterThan,
                field: "trust.trust_score".to_string(),
                value: json!(0.0),
            },
            action: PolicyDecision::Allow,
        };

        let policy = Policy {
            id: Uuid::new_v4(),
            version: 1,
            variables: HashMap::new(),
            groups: vec![RuleGroup {
                id: "group1".to_string(),
                name: "Fraud Rules".to_string(),
                rules: vec![rule_1, rule_2],
            }],
        };

        let trust = TrustScore {
            score: 0.1, // Risk will be 0.9
            confidence: 0.9,
            reasons: vec![],
        };

        let context = EventContext {
            product: "demo".to_string(),
            event_type: "transfer".to_string(),
            ip_address: None,
            country: Some("RU".to_string()),
            device_fingerprint: None,
            user_agent: None,
            variables: HashMap::new(),
            payload: json!({}),
        };

        let result = PolicyEngine::evaluate(&policy, &trust, &context, false);
        assert_eq!(result.decision, PolicyDecision::Block);
        assert_eq!(result.matched_rules[0].rule_id, "block_high_risk_geo");
    }
}
