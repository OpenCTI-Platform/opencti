import type { Resolvers } from '../../../generated/graphql';
import { storeLoadById } from '../../../database/middleware-loader';
import { loadCreator, loadCreators } from '../../../database/members';
import { ENTITY_TYPE_HUNT } from '../hunt-types';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../../schema/stixDomainObject';
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
  reportHuntConnectorCheck,
  reportHuntRun,
  resolveHuntRunIocResults,
  retryHuntRun,
  testHuntConnectorConnection,
  setHuntRunVerdict,
  toHuntConnectorView,
  triageHuntRun,
} from './huntRun-domain';
import type { BasicStoreEntityConnector } from '../../../types/connector';
import { huntRunQueueReason } from '../hunt-dispatch';
import { huntRunFailureReason } from '../hunt-logic';
import { annotateHuntRunHits } from '../huntHitRecord/huntHitRecord-domain';

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
    technique: (run, _, context) => (run.technique_id
      ? storeLoadById(context, context.user, run.technique_id, ENTITY_TYPE_ATTACK_PATTERN) as any
      : null),
    creators: (run, _, context) => loadCreators(context, context.user, run),
    triggeredBy: (run, _, context) => (run.triggered_by ? loadCreator(context, context.user, run.triggered_by) : null),
    objectMarking: (run, _, context) => context.batch.markingsBatchLoader.load(run),
    results: (run, { first, after }, context) => findHuntRunResults(context, context.user, run, first ?? 50, after) as any,
    result_ids: (run, _, context) => findHuntRunResultIds(context, context.user, run),
    results_summary: (run, _, context) => findHuntRunResultsSummary(context, context.user, run),
    ioc_results: (run, _, context) => resolveHuntRunIocResults(context, context.user, run) as any,
    hits_sample: (run, _, context) => annotateHuntRunHits(context, run) as any,
    time_window_continued: (run) => !!run.continues_run_id,
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
  Connector: {
    hunt: (connector) => {
      // The Connector type is not mapped to its store entity in the generated resolver types
      const stored = connector as unknown as BasicStoreEntityConnector;
      return stored.hunt_platform ? toHuntConnectorView(stored) : null;
    },
  },
  Mutation: {
    huntRunRetry: (_, { id }, context) => retryHuntRun(context, context.user, id),
    huntRunSetVerdict: (_, { id, input }, context) => setHuntRunVerdict(context, context.user, id, input),
    huntRunTriage: (_, { id }, context) => triageHuntRun(context, context.user, id),
    huntRunReport: (_, { id, input }, context) => reportHuntRun(context, context.user, id, input),
    huntRunEvidenceAdd: (_, { id, input }, context) => addHuntRunEvidence(context, context.user, id, input),
    huntConnectorRegister: (_, { input }, context) => registerHuntConnector(context, context.user, input),
    huntConnectorTestConnection: (_, { id }, context) => testHuntConnectorConnection(context, context.user, id) as any,
    huntConnectorCheckReport: (_, { input }, context) => reportHuntConnectorCheck(context, context.user, input) as any,
  },
};

export default huntRunResolvers;
