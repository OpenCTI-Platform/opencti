import type { StixEntities } from './general';
import type { StixRelation } from './stix-sro';
import type { StoreObject } from './store';
import { UpdateEvent } from './event';

interface RuleFilters {
  types: Array<string>;
  fromTypes?: Array<string>;
  toTypes?: Array<string>;
}

interface RuleScanAttribute {
  name: string;
  dependency?: boolean;
}

interface RuleScope {
  filters: RuleFilters;
  attributes: Array<RuleScanAttribute>;
}

interface RuleBehavior {
  ruleId: string;
  attribute: string;
  operation: string;
}

interface RelationTypes {
  leftType: string;
  rightType: string;
  creationType: string;
}

interface StepDefinition {
  action?: string;
  source: string;
  source_color: string;
  relation?: string;
  target?: string;
  target_color?: string;
  identifier?: string;
  identifier_color?: string;
}

interface DisplayDefinition {
  if: Array<StepDefinition>;
  then: Array<StepDefinition>;
}

interface RuleDefinition {
  id: string;
  name: string;
  description: string;
  category: string;
  display: DisplayDefinition;
  scan: RuleFilters;
  scopes: Array<RuleScope>;
  behaviors: Array<RuleBehavior>;
}

interface RuleRuntime extends RuleDefinition {
  activated?: boolean;
  insert: (element: StixEntities | StixRelation) => Promise<void>;
  update: (element: StixEntities | StixRelation, event: UpdateEvent) => Promise<void>;
  clean: (element: StoreObject, deletedDependencies: Array<string>) => Promise<void>;
}
