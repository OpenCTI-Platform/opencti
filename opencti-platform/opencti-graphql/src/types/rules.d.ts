import type { StixEntities } from './general';
import type { StixRelation } from './stix-2-1-sro';
import type { StoreObject } from './store';
import type { UpdateEvent } from './event';
import type { AuthContext } from './user';

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

interface RelationTypes {
  leftType: string;
  rightType: string;
  creationType: string;
  isSource?: boolean;
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
}

type CreateInferredRelationCallbackFunction = (context: AuthContext, input: any, ruleContent: any, opts?: any | undefined) => Promise<any>;
type CreateInferredEntityCallbackFunction = (context: AuthContext, input: any, ruleContent: any, type: string) => Promise<any>;

interface RuleRuntime extends RuleDefinition {
  activated?: boolean;
  insert: (
    element: StixEntities | StixRelation,
    createInferredEntityCallback: CreateInferredEntityCallbackFunction,
    createInferredRelationCallback: CreateInferredRelationCallbackFunction,
  ) => Promise<void>;
  update: (element: StixEntities | StixRelation, event: UpdateEvent) => Promise<void>;
  clean: (element: StoreObject, deletedDependencies: Array<string>) => Promise<void>;
}
