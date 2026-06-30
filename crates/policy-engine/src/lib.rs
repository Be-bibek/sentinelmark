use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use context_engine::EventContext;
use trust_engine::TrustScore;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    RequireMFA,
    RequireApproval,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Equals,
    NotEquals,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    In,
    NotIn,
    Contains,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Condition {
    And { and: Vec<Condition> },
    Or { or: Vec<Condition> },
    Not { not: Box<Condition> },
    Expression {
        operator: Operator,
        field: String,
        value: Value,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: i32,
    pub enabled: bool,
    pub continue_processing: bool,
    pub condition: Condition,
    pub action: PolicyDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleGroup {
    pub id: String,
    pub name: String,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: Uuid,
    pub version: i32,
    pub variables: HashMap<String, Value>,
    pub groups: Vec<RuleGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRuleInfo {
    pub rule_id: String,
    pub rule_name: String,
    pub action: PolicyDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    pub decision: PolicyDecision,
    pub matched_rules: Vec<MatchedRuleInfo>,
    pub is_dry_run: bool,
}

pub struct PolicyEngine;

impl PolicyEngine {
    pub fn evaluate(
        policy: &Policy,
        trust: &TrustScore,
        context: &EventContext,
        is_dry_run: bool,
    ) -> PolicyResult {
        let mut matched_rules = Vec::new();
        let mut final_decision = PolicyDecision::Allow;
        let mut stop_processing = false;

        // Flatten rules and sort by priority (highest first)
        let mut all_rules: Vec<&Rule> = policy
            .groups
            .iter()
            .flat_map(|g| g.rules.iter())
            .filter(|r| r.enabled)
            .collect();
        all_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        for rule in all_rules {
            if stop_processing {
                break;
            }

            if Self::evaluate_condition(&rule.condition, trust, context, &policy.variables) {
                matched_rules.push(MatchedRuleInfo {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    action: rule.action.clone(),
                });

                // In dry run, we log matches but don't let them override the final decision.
                if !is_dry_run {
                    final_decision = rule.action.clone();
                    if !rule.continue_processing {
                        stop_processing = true;
                    }
                }
            }
        }

        PolicyResult {
            decision: final_decision,
            matched_rules,
            is_dry_run,
        }
    }

    fn evaluate_condition(
        condition: &Condition,
        trust: &TrustScore,
        context: &EventContext,
        variables: &HashMap<String, Value>,
    ) -> bool {
        match condition {
            Condition::And { and } => and.iter().all(|c| Self::evaluate_condition(c, trust, context, variables)),
            Condition::Or { or } => or.iter().any(|c| Self::evaluate_condition(c, trust, context, variables)),
            Condition::Not { not } => !Self::evaluate_condition(not, trust, context, variables),
            Condition::Expression { operator, field, value } => {
                let resolved_value = Self::resolve_variable(value, variables);
                let field_value = Self::extract_field(field, trust, context);
                
                Self::compare(&field_value, operator, &resolved_value)
            }
        }
    }

    fn resolve_variable(value: &Value, variables: &HashMap<String, Value>) -> Value {
        if let Some(s) = value.as_str() {
            if s.starts_with("${") && s.ends_with("}") {
                let var_name = &s[2..s.len()-1];
                if let Some(val) = variables.get(var_name) {
                    return val.clone();
                }
            }
        }
        value.clone()
    }

    fn extract_field(field: &str, trust: &TrustScore, context: &EventContext) -> Option<Value> {
        if field == "trust.risk_score" {
            return Some(serde_json::json!(1.0 - trust.score));
        } else if field == "trust.trust_score" {
            return Some(serde_json::json!(trust.score));
        } else if field == "context.country" {
            return context.country.as_ref().map(|s| serde_json::json!(s));
        } else if field == "context.product" {
            return Some(serde_json::json!(context.product));
        }
        
        if field.starts_with("event.") {
            let key = &field[6..];
            return context.payload.get(key).cloned();
        }
        
        None
    }

    fn compare(field_value: &Option<Value>, operator: &Operator, target_value: &Value) -> bool {
        let field_val = match field_value {
            Some(v) => v,
            None => return false, // Field not present, expression is false
        };

        match operator {
            Operator::Equals => field_val == target_value,
            Operator::NotEquals => field_val != target_value,
            Operator::GreaterThan => {
                if let (Some(f), Some(t)) = (field_val.as_f64(), target_value.as_f64()) {
                    f > t
                } else {
                    false
                }
            }
            Operator::LessThan => {
                if let (Some(f), Some(t)) = (field_val.as_f64(), target_value.as_f64()) {
                    f < t
                } else {
                    false
                }
            }
            Operator::GreaterThanOrEqual => {
                if let (Some(f), Some(t)) = (field_val.as_f64(), target_value.as_f64()) {
                    f >= t
                } else {
                    false
                }
            }
            Operator::LessThanOrEqual => {
                if let (Some(f), Some(t)) = (field_val.as_f64(), target_value.as_f64()) {
                    f <= t
                } else {
                    false
                }
            }
            Operator::In => {
                if let Some(arr) = target_value.as_array() {
                    arr.contains(field_val)
                } else {
                    false
                }
            }
            Operator::NotIn => {
                if let Some(arr) = target_value.as_array() {
                    !arr.contains(field_val)
                } else {
                    false
                }
            }
            Operator::Contains => {
                if let (Some(s), Some(target)) = (field_val.as_str(), target_value.as_str()) {
                    s.contains(target)
                } else {
                    false
                }
            }
        }
    }
}
mod tests;
