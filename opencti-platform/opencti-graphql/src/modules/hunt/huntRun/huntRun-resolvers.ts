import type { Resolvers } from '../../../generated/graphql';
import { storeLoadById } from '../../../database/middleware-loader';
import { loadCreator, loadCreators } from '../../../database/members';
import { ENTITY_TYPE_HUNT } from '../hunt-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../securityPlatform/securityPlatform-types';
import { HUNT_EVIDENCE_KIND_TOOL_RESULT } from './huntRun-types';
import {
  addHuntRunEvidence,
  findHuntConnectors,
  findHuntRunById,
  findHuntRunResults,
  findHuntRunsPaginated,
  registerHuntConnector,
  reportHuntRun,
  retryHuntRun,
  setHuntRunVerdict,
  triageHuntRun,
} from './huntRun-domain';

const huntRunResolvers: Resolvers = {
  Query: {
    huntRun: (_, { id }, context) => findHuntRunById(context, context.user, id),
    huntRuns: (_, args, context) => findHuntRunsPaginated(context, context.user, args),
    huntConnectors: (_, { onlyAlive }, context) => findHuntConnectors(context, onlyAlive ?? false),
  },
  HuntRun: {
    hunt: (run, _, context) => storeLoadById(context, context.user, run.hunt_id, ENTITY_TYPE_HUNT),
    securityPlatform: (run, _, context) => (run.security_platform_id
      ? storeLoadById(context, context.user, run.security_platform_id, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM)
      : null),
    creators: (run, _, context) => loadCreators(context, context.user, run),
    triggeredBy: (run, _, context) => (run.triggered_by ? loadCreator(context, context.user, run.triggered_by) : null),
    objectMarking: (run, _, context) => context.batch.markingsBatchLoader.load(run),
    results: (run, { first }, context) => findHuntRunResults(context, context.user, run, first ?? 50) as any,
  },
  // A telemetry hit in the program-wide evidence shape: a tool result labelled by its field, quoting its preview
  HuntEvidence: {
    kind: () => HUNT_EVIDENCE_KIND_TOOL_RESULT,
    label: (evidence) => evidence.field,
    quote: (evidence) => evidence.value_preview ?? null,
    href: () => null,
    opencti_id: () => null,
    entity_type: () => null,
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
