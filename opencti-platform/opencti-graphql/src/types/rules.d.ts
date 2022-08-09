import type { Event } from './event';
import type { StixEntities } from './general';
import type { StixRelation } from './stix-sro';
import type { StoreObject } from './store';

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

interface RuleDefinition {
  id: string;
  name: string;
  description: string;
  scan: RuleFilters;
  scopes: Array<RuleScope>;
  behaviors: Array<RuleBehavior>;
}

interface RuleRuntime extends RuleDefinition {
  activated?: boolean;
  insert: (element: StixEntities | StixRelation) => Promise<Array<Event>>;
  update: (element: StixEntities | StixRelation) => Promise<Array<Event>>;
  clean: (element: StoreObject, deletedDependencies: Array<string>) => Promise<Array<Event>>;
}
