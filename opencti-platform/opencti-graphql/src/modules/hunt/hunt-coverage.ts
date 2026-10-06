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
import { type BasicStoreEntityHuntRun, ENTITY_TYPE_HUNT_RUN, HUNT_RUN_STATUS_COMPLETED } from './huntRun/huntRun-types';
import { mergeHuntDetectedCoverage } from './hunt-coverage-utils';
import { withHuntLock } from './hunt-lock';

const HUNT_COVERAGE_LOCK = 'hunt_coverage';

/**
 * After an emulation-triggered run completes, the hunt efficacy for the emulated technique is written as
 * coverage_information hunt_detected on the has-covered relationships of the security coverage results:
 * 100 when at least one completed hunt run of the same security coverage, inject and technique has hits, 0 otherwise.
 * The same emulation can be validated for several security coverages: each one only reads its own validation runs.
 * The coverage has-covered relationship is per result and technique, shared by every security platform: the score
 * reads whether a hunt caught the technique on any platform of the emulation. Emulation runs and their retries carry
 * the inject, the technique and the security coverage.
 * The runs of one validation finish under their own run locks, possibly on several platform nodes: the read of the
 * sibling runs and the write of the relationships hold one lock per security coverage, inject and technique (the
 * relationships are shared by every security platform), so a run without hits can never write over the detection
 * of a run with hits computed concurrently.
 */
export const writeHuntCoverageResult = async (context: AuthContext, run: BasicStoreEntityHuntRun): Promise<number> => {
  if (!run.security_coverage_id || !run.technique_id || !run.aev_inject_id) {
    return 0;
  }
  const securityCoverageId = run.security_coverage_id;
  const injectId = run.aev_inject_id;
  const techniqueId = run.technique_id;
  const coverage = await internalLoadById<BasicStoreEntitySecurityCoverage>(context, HUNT_MANAGER_USER, securityCoverageId, { type: ENTITY_TYPE_SECURITY_COVERAGE });
  const resultIds = coverage?.[RELATION_RESULT_OF] ?? [];
  if (resultIds.length === 0) {
    logApp.info('[OPENCTI-MODULE] Hunt validation has no security coverage result to update', { runId: run.internal_id, securityCoverageId });
    return 0;
  }
  return withHuntLock(`${HUNT_COVERAGE_LOCK}_${securityCoverageId}_${injectId}_${techniqueId}`, async () => {
    const siblingRuns = await fullEntitiesList<BasicStoreEntityHuntRun>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_HUNT_RUN], {
      filters: {
        mode: FilterMode.And,
        filters: [
          { key: ['security_coverage_id'], values: [securityCoverageId] },
          { key: ['aev_inject_id'], values: [injectId] },
          { key: ['technique_id'], values: [techniqueId] },
          { key: ['hunt_run_status'], values: [HUNT_RUN_STATUS_COMPLETED] },
        ],
        filterGroups: [],
      },
      noFiltersChecking: true,
    });
    // The run being finalized counts even before the index exposes its completed status
    const detected = (run.hunt_run_status === HUNT_RUN_STATUS_COMPLETED && (run.hits_count ?? 0) > 0)
      || siblingRuns.some((siblingRun) => (siblingRun.hits_count ?? 0) > 0);
    const relations = await fullRelationsList<BasicStoreRelation & { coverage_information?: CoverageInformation[] }>(
      context,
      HUNT_MANAGER_USER,
      RELATION_HAS_COVERED,
      { fromId: resultIds, toId: techniqueId },
    );
    for (let index = 0; index < relations.length; index += 1) {
      const relation = relations[index];
      const coverageInformation = mergeHuntDetectedCoverage(relation.coverage_information, detected);
      await patchAttribute(context, HUNT_MANAGER_USER, relation.internal_id, RELATION_HAS_COVERED, { coverage_information: coverageInformation });
    }
    return relations.length;
  });
};
