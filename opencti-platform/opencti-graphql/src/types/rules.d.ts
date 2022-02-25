import type { Event } from './event';
import type { StixObject, StixEntities } from './general';

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

interface RuleDefinition {
  id: string;
  name: string;
  description: string;
  scan: RuleFilters;
  scopes: Array<RuleScope>;
  behaviors: Array<RuleBehavior>;
}

interface Rule extends RuleDefinition {
  insert: (element: StixEntities | StixRelation) => Promise<Array<Event>>;
  update: (element: StixEntities | StixRelation) => Promise<Array<Event>>;
  clean: (element: StixObject, deletedDependencies: Array<string>) => Promise<Array<Event>>;
}
