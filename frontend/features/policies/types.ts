export type PolicyAction = "ALLOW" | "BLOCK" | "MFA" | "CHALLENGE";
export type Operator = ">" | "<" | "==" | "!=" | "IN" | "NOT_IN";
export type ConditionType = "AND" | "OR";

export interface FlatCondition {
  id: string;
  field: string;
  operator: Operator;
  value: string | number | string[];
}

export interface Rule {
  id: string;
  name: string;
  priority: number;
  enabled: boolean;
  action: PolicyAction;
  conditionType: ConditionType;
  conditions: FlatCondition[];
}

export interface RuleGroup {
  id: string;
  name: string;
  rules: Rule[];
}

export interface PolicyVariable {
  id: string;
  key: string;
  value: string;
}

export interface PolicyDraft {
  id: string;
  name: string;
  status: "active" | "draft" | "archived";
  version: number;
  variables: PolicyVariable[];
  groups: RuleGroup[];
}
