import type { HuntRunRuleResult, Resolvers } from '../../../generated/graphql';
import { storeLoadById } from '../../../database/middleware-loader';
import { loadCreator, loadCreators } from '../../../database/members';
import { ENTITY_TYPE_HUNT } from '../hunt-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../securityPlatform/securityPlatform-types';
import { HUNT_EVIDENCE_KIND_TOOL_RESULT } from './huntRun-types';
import {
  addHuntRunEvidence,
  findHuntConnectors,
  findHuntRunById,
  findHuntRunResultIds,
  findHuntRunResults,
  findHuntRunResultsSummary,
  findHuntRunsPaginated,
  isAutoEscalatedHuntRun,
  isHuntRunHuntDeleted,
  registerHuntConnector,
  reportHuntRun,
  resolveHuntRunIocResults,
  retryHuntRun,
  setHuntRunVerdict,
  triageHuntRun,
} from './huntRun-domain';
import { huntRunQueueReason } from '../hunt-dispatch';
import { huntRunFailureReason } from '../hunt-logic';
import { annotateHuntRunHits } from '../huntHitRecord/huntHitRecord-domain';
import { huntRunEntityMatched } from './huntRun-iocs';
import { resolveHuntRunIncidentLink } from '../hunt-incident';

const huntRunResolvers: Resolvers = {
  Query: {
    huntRun: (_, { id }, context) => findHuntRunById(context, context.user, id),
    huntRuns: (_, args, context) => findHuntRunsPaginated(context, context.user, args),
    huntConnectors: (_, { onlyAlive }, context) => findHuntConnectors(context, context.user, onlyAlive ?? false),
  },
  HuntRun: {
    hunt: (run, _, context) => storeLoadById(context, context.user, run.hunt_id, ENTITY_TYPE_HUNT),
    hunt_deleted: (run, _, context) => isHuntRunHuntDeleted(context, run),
    queue_reason: (run, _, context) => huntRunQueueReason(context, run),
    failure_reason: (run) => huntRunFailureReason(run),
    auto_escalation: (run) => isAutoEscalatedHuntRun(run),
    unresolved_techniques: (run) => run.unresolved_techniques ?? [],
    securityPlatform: (run, _, context) => (run.security_platform_id
      ? storeLoadById(context, context.user, run.security_platform_id, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM)
      : null),
    creators: (run, _, context) => loadCreators(context, context.user, run),
    triggeredBy: (run, _, context) => (run.triggered_by ? loadCreator(context, context.user, run.triggered_by) : null),
    objectMarking: (run, _, context) => context.batch.markingsBatchLoader.load(run),
    results: (run, { first, after }, context) => findHuntRunResults(context, context.user, run, first ?? 50, after) as any,
    result_ids: (run, _, context) => findHuntRunResultIds(context, context.user, run),
    results_summary: (run, _, context) => findHuntRunResultsSummary(context, context.user, run),
    ioc_results: (run, _, context) => resolveHuntRunIocResults(context, context.user, run) as any,
    entity_matched: (run, { id }) => huntRunEntityMatched(run, id),
    hits_sample: (run, _, context) => annotateHuntRunHits(context, context.user, run) as any,
    time_window_continued: (run) => !!run.continues_run_id,
    incident_id: async (run, _, context) => (await resolveHuntRunIncidentLink(context, context.user, run)).incident_id,
    draft_id: async (run, _, context) => (await resolveHuntRunIncidentLink(context, context.user, run)).draft_id,
    rule_results: (run) => (run.rule_results ?? []) as HuntRunRuleResult[],
  },
  // A telemetry hit in the program-wide evidence shape: a tool result labelled by its field, quoting its preview
  HuntEvidence: {
    kind: () => HUNT_EVIDENCE_KIND_TOOL_RESULT,
    label: (evidence) => evidence.field,
    quote: (evidence) => evidence.value_preview ?? null,
    href: () => null,
    opencti_id: () => null,
    entity_type: () => null,
    matched: (evidence) => evidence.matched === true,
  },
  HuntHit: {
    matched: (hit) => hit.matched ?? [],
  },
  HuntHitField: {
    value_complete: (field) => field.value_complete === true,
  },
  HuntConnector: {
    securityPlatform: (connector, _, context) => (connector.security_platform_id
      ? storeLoadById(context, context.user, connector.security_platform_id, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM)
      : null),
  },
  Mutation: {
    huntRunRetry: (_, { id }, context) => retryHuntRun(context, context.user, id),
    huntRunSetVerdict: (_, { id, input }, context) => setHuntRunVerdict(context, context.user, id, input),
    huntRunTriage: (_, { id }, context) => triageHuntRun(context, context.user, id),
    huntRunReport: (_, { id, input }, context) => reportHuntRun(context, context.user, id, input),
    huntRunEvidenceAdd: (_, { id, input }, context) => addHuntRunEvidence(context, context.user, id, input),
    huntConnectorRegister: (_, { input }, context) => registerHuntConnector(context, context.user, input),
  },
};

export default huntRunResolvers;
