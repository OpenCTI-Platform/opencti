import type { Resolvers } from '../../generated/graphql';
import { BUS_TOPICS } from '../../config/conf';
import { subscribeToInstanceEvents } from '../../graphql/subscriptionWrapper';
import { stixDomainObjectCleanContext, stixDomainObjectEditContext } from '../../domain/stixDomainObject';
import {
  addHunt,
  addHuntProposal,
  assistHunt,
  findHuntById,
  findHuntsPaginated,
  huntAddRelation,
  huntDelete,
  huntDeleteRelation,
  huntEditField,
  huntSigmaValidation,
  importHuntPack,
  loadHuntIocSet,
  loadHuntRefs,
  loadHuntScopePlatforms,
  planHunt,
} from './hunt-domain';
import { computeHuntReadiness } from './hunt-readiness';
import { HUNT_IOC_FILTER_MAX, previewHuntIocFilter } from './hunt-iocs';
import { deriveHuntContent, HUNT_MAX_RELATED_SOURCES } from './hunt-derivation';
import { exportHuntPack } from './hunt-pack';
import { validateSigmaRule } from './hunt-sigma';
import { findUnresolvedAttackTechniques } from './hunt-logic';
import { ENTITY_TYPE_HUNT, RELATION_HUNT_SOURCES, RELATION_HUNT_TARGETS, RELATION_HUNT_TECHNIQUES } from './hunt-types';
import { HUNT_CONFIG, HUNT_DEFAULT_EXPECTED_OBSERVABLES, HUNT_MAX_SIGMA_RULES, huntRuleKey, storedSigmaRules } from './hunt-utils';
import { computeHuntStatistics, findHuntRunsForHunt, findHuntTranslationsView, startHuntPreview, startHuntRuns } from './huntRun/huntRun-domain';
import { storeLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../securityPlatform/securityPlatform-types';
import { findHuntKnownHits } from './huntHitRecord/huntHitRecord-domain';
import { findHuntEntityActivity } from './huntRun/huntRun-iocs';

const huntResolvers: Resolvers = {
  Query: {
    hunt: (_, { id }, context) => findHuntById(context, context.user, id),
    hunts: (_, args, context) => findHuntsPaginated(context, context.user, args),
    huntSigmaValidate: (_, { sigma_rule }) => validateSigmaRule(sigma_rule),
    huntConfiguration: () => ({
      min_schedule_interval_minutes: HUNT_CONFIG.minScheduleIntervalMinutes,
      default_expected_observables: HUNT_DEFAULT_EXPECTED_OBSERVABLES,
      schedule_lookback_minutes: HUNT_CONFIG.scheduleLookbackMinutes,
      max_time_window_hours: HUNT_CONFIG.maxTimeWindowHours,
      max_results_per_run: HUNT_CONFIG.maxResultsPerRun,
      max_sigma_rules: HUNT_MAX_SIGMA_RULES,
      max_iocs_per_run: HUNT_CONFIG.maxIocsPerRun,
      max_filter_entities_per_run: HUNT_IOC_FILTER_MAX,
      max_related_sources: HUNT_MAX_RELATED_SOURCES,
    }),
    huntStatistics: (_, args, context) => computeHuntStatistics(context, context.user, args),
    huntPackExport: (_, { ids }, context) => exportHuntPack(context, context.user, ids),
    huntDerivedContent: (_, { entityId }, context) => deriveHuntContent(context, context.user, entityId),
    huntEntityActivity: (_, { id }, context) => findHuntEntityActivity(context, context.user, id),
  },
  Hunt: {
    huntTargets: (hunt, _, context) => loadHuntRefs<any>(context, context.user, hunt, RELATION_HUNT_TARGETS),
    huntTechniques: (hunt, _, context) => loadHuntRefs<any>(context, context.user, hunt, RELATION_HUNT_TECHNIQUES),
    huntSources: (hunt, _, context) => loadHuntRefs<any>(context, context.user, hunt, RELATION_HUNT_SOURCES),
    scopePlatforms: (hunt, _, context) => loadHuntScopePlatforms(context, context.user, hunt),
    sigmaValidation: (hunt) => huntSigmaValidation(hunt),
    sigma_rules: (hunt) => storedSigmaRules(hunt),
    sigma_rule_keys: (hunt) => storedSigmaRules(hunt).map(huntRuleKey),
    translations: (hunt, _, context) => findHuntTranslationsView(context, context.user, hunt),
    readiness: (hunt, _, context) => computeHuntReadiness(context, context.user, hunt),
    escalate_manual_runs: (hunt) => hunt.escalate_manual_runs === true,
    iocSet: (hunt, { first }, context) => loadHuntIocSet(context, context.user, hunt, first),
    iocFilterPreview: (hunt, { filters, sort }, context) => previewHuntIocFilter(context, hunt, { filters, sort }),
    runs: (hunt, args, context) => findHuntRunsForHunt(context, context.user, hunt.id, args),
    knownHits: (hunt, _, context) => findHuntKnownHits(context, context.user, hunt.id),
    statistics: (hunt, args, context) => computeHuntStatistics(context, context.user, { ...args, huntId: hunt.id }),
    toStixBundle: (hunt, _, context) => exportHuntPack(context, context.user, [hunt.id]),
  },
  HuntTranslation: {
    securityPlatform: (translation, _, context) => (translation.security_platform_id
      ? storeLoadById(context, context.user, translation.security_platform_id, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM) as any
      : null),
  },
  HuntSigmaValidation: {
    unresolved_attack_techniques: (validation, _, context) => findUnresolvedAttackTechniques(context, context.user, validation.attack_techniques),
  },
  Mutation: {
    huntAdd: (_, { input }, context) => addHunt(context, context.user, input),
    huntProposalAdd: (_, { input, draftName }, context) => addHuntProposal(context, context.user, input, draftName),
    huntDelete: (_, { id }, context) => huntDelete(context, context.user, id),
    huntFieldPatch: (_, { id, input, commitMessage, references }, context) => {
      return huntEditField(context, context.user, id, input, { commitMessage, references });
    },
    huntContextPatch: (_, { id, input }, context) => stixDomainObjectEditContext(context, context.user, id, input),
    huntContextClean: (_, { id }, context) => stixDomainObjectCleanContext(context, context.user, id),
    huntRelationAdd: (_, { id, input }, context) => huntAddRelation(context, context.user, id, input),
    huntRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return huntDeleteRelation(context, context.user, id, toId, relationshipType);
    },
    huntRunStart: (_, { id, input }, context) => startHuntRuns(context, context.user, id, input),
    huntTestQuery: (_, { id, securityPlatformId }, context) => startHuntPreview(context, context.user, id, securityPlatformId),
    huntPlan: (_, { input }, context) => planHunt(context, context.user, input),
    huntAssist: (_, { input }, context) => assistHunt(context, context.user, input),
    huntPackImport: (_, { file }, context) => importHuntPack(context, context.user, file),
  },
  Subscription: {
    hunt: {
      resolve: (payload: any) => {
        return payload.instance;
      },
      subscribe: (_: any, { id }: any, context: any) => {
        const bus = BUS_TOPICS[ENTITY_TYPE_HUNT];
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC, bus.ADDED_TOPIC], { type: ENTITY_TYPE_HUNT, notifySelf: true });
      },
    },
  },
};

export default huntResolvers;
