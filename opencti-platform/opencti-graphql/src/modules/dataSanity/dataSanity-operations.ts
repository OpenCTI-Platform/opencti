import { caseSensitiveDuplicatedId, caseSensitiveDuplicatedIdDryRun } from './operations/caseSensitiveDuplicatedId';
import type { AuthContext } from '../../types/user';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION } from '../../schema/stixDomainObject';

export type ExecutionType = 'run_once'; // For now, we only need one, but later we will have 'on_demand', 'periodic' or 'live' scripts.
// Map of entity_type or relation_type to the number of impacted elements
export type ImpactedElementsMap = Record<string, number>;

export interface SanityOperationRunOutput {
  impact: {
    total: number;
    detail: ImpactedElementsMap; // detailed estimated impacted elements per entity/relation type
  };
}

export interface SanityOperation {
  identifier: string; // unique name to identify the sanity operation
  execution_type: ExecutionType;
  eligibleEntityTypes: string[];

  // dry run: returns estimated impact without modifying data, this function should be fast to run.
  dryRun: (context: AuthContext) => Promise<SanityOperationRunOutput>;

  // actual run: applies the operation and returns impact
  operationRun: (context: AuthContext) => Promise<SanityOperationRunOutput>;

  // Description of the operations that will be displayed on UI
  description: string;
  // Human-readable short name
  display_name: string;
}

/*
  Hard coded list of available operations
 */
const CASE_SENSITIVE_DUPLICATED_ID_ENTITY_TYPES = [ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION];

const SANITY_OPERATIONS: SanityOperation[] = [
  {
    identifier: 'caseSensitiveDuplicatedId',
    dryRun: caseSensitiveDuplicatedIdDryRun(CASE_SENSITIVE_DUPLICATED_ID_ENTITY_TYPES),
    operationRun: caseSensitiveDuplicatedId(CASE_SENSITIVE_DUPLICATED_ID_ENTITY_TYPES),
    execution_type: 'run_once',
    description: 'Find attack pattern or course of action that are duplicated when ignoring case and merge duplicates.',
    display_name: 'Case sensitive Duplicated ID',
    eligibleEntityTypes: CASE_SENSITIVE_DUPLICATED_ID_ENTITY_TYPES,
  },
];

export const sanityOperationList = () => {
  return SANITY_OPERATIONS;
};
