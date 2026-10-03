import type { AuthContext } from '../../types/user';
import type { BasicStoreRelation } from '../../types/store';
import { logApp } from '../../config/conf';
import { patchAttribute } from '../../database/middleware';
import { fullEntitiesList, fullRelationsList, internalLoadById } from '../../database/middleware-loader';
import { RELATION_HAS_COVERED } from '../../schema/stixCoreRelationship';
import { FilterMode } from '../../generated/graphql';
import { HUNT_MANAGER_USER } from '../../utils/access';
import { ENTITY_TYPE_SECURITY_COVERAGE, type BasicStoreEntitySecurityCoverage } from '../securityCoverage/securityCoverage-types';
import { RELATION_RESULT_OF, type CoverageInformation } from '../securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { type BasicStoreEntityHuntRun, ENTITY_TYPE_HUNT_RUN, HUNT_RUN_STATUS_COMPLETED, HUNT_RUN_TRIGGER_EMULATION } from './huntRun/huntRun-types';
import { mergeHuntDetectedCoverage } from './hunt-coverage-utils';

/**
 * After an emulation-triggered run completes, the hunt efficacy for the emulated technique is written as
 * coverage_information hunt_detected on the has-covered relationships of the security coverage results:
 * 100 when at least one completed hunt run of the same inject and technique has hits, 0 otherwise.
 */
export const writeHuntCoverageResult = async (context: AuthContext, run: BasicStoreEntityHuntRun): Promise<number> => {
  if (run.hunt_run_trigger !== HUNT_RUN_TRIGGER_EMULATION || !run.security_coverage_id || !run.technique_id || !run.aev_inject_id) {
    return 0;
  }
  const coverage = await internalLoadById<BasicStoreEntitySecurityCoverage>(context, HUNT_MANAGER_USER, run.security_coverage_id, { type: ENTITY_TYPE_SECURITY_COVERAGE });
  const resultIds = coverage?.[RELATION_RESULT_OF] ?? [];
  if (resultIds.length === 0) {
    logApp.info('[OPENCTI-MODULE] Hunt validation has no security coverage result to update', { runId: run.internal_id, securityCoverageId: run.security_coverage_id });
    return 0;
  }
  const siblingRuns = await fullEntitiesList<BasicStoreEntityHuntRun>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_HUNT_RUN], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['aev_inject_id'], values: [run.aev_inject_id] },
        { key: ['technique_id'], values: [run.technique_id] },
        { key: ['hunt_run_status'], values: [HUNT_RUN_STATUS_COMPLETED] },
      ],
      filterGroups: [],
    },
    noFiltersChecking: true,
  });
  const detected = siblingRuns.some((siblingRun) => (siblingRun.hits_count ?? 0) > 0);
  const relations = await fullRelationsList<BasicStoreRelation & { coverage_information?: CoverageInformation[] }>(
    context,
    HUNT_MANAGER_USER,
    RELATION_HAS_COVERED,
    { fromId: resultIds, toId: run.technique_id },
  );
  for (let index = 0; index < relations.length; index += 1) {
    const relation = relations[index];
    const coverageInformation = mergeHuntDetectedCoverage(relation.coverage_information, detected);
    await patchAttribute(context, HUNT_MANAGER_USER, relation.internal_id, RELATION_HAS_COVERED, { coverage_information: coverageInformation });
  }
  return relations.length;
};
