import type { Resolvers } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import { loadCreator } from '../../database/members';
import { connector as loadConnector } from '../../database/repository';
import { storeLoadById } from '../../database/middleware-loader';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import { connectorIdFromIngestId } from '../../domain/connector';
import { ENTITY_TYPE_PIR } from '../pir/pir-types';
import {
  editSourceIntelligenceSettings,
  findLatestScorecard,
  findSourceById,
  findSourceOverlap,
  findSourceScorecards,
  findSourcesPaginated,
  getSourceIntelligenceSettings,
  getSourceIntelligenceStatus,
  isSourceIntelligenceEnabled,
  isSourceIntelligenceRunning,
  maskRestrictedNames,
  maskRestrictedNamesInJson,
  parseJsonRecord,
  requestSourceIntelligenceRecompute,
  restrictedRecommendationNames,
  sourceEditField,
  sourceSetCost,
} from './sourceIntelligence-domain';
import {
  applySourceRecommendation,
  countRecommendations,
  dismissSourceRecommendation,
  findRecommendationById,
  findRecommendationsPaginated,
  revertSourceRecommendation,
} from './sourceIntelligence-recommendations';
import { deployCollectionGapConnector, findCollectionGaps } from './sourceIntelligence-gaps';
import {
  createIntelligenceRoiDashboard,
  SCORECARD_METRICS,
  sourceScorecardsDistribution,
  sourceScorecardsNumber,
  sourceScorecardsScatter,
  sourceScorecardsTimeSeries,
} from './sourceIntelligence-widgets';
import { RECOMMENDATION_ADD_CONNECTOR, SOURCE_KIND_CONNECTOR, SOURCE_KIND_INGESTION_FEED } from './sourceIntelligence-types';
import { requiredSettingsOfImage } from './sourceIntelligence-deployment';

// PIR relevance is measured in Enterprise Edition only: the values stored before a license downgrade are not served
const enterpriseValue = async (context: AuthContext, value: number | null | undefined) => {
  return (await isEnterpriseEdition(context)) ? (value ?? null) : null;
};

// Recommendation texts embed the names of their sources: names of restricted authors are masked for the requesting user
type MaskedRecommendationField = 'name' | 'rationale' | 'payload' | 'recommendation_evidence' | 'apply_result' | 'error_message' | 'dismiss_reason';

// Every stored text of a recommendation can quote the name of a marked author: none reaches a user who cannot see it
const maskedRecommendationText = async (context: AuthContext, recommendation: any, field: MaskedRecommendationField): Promise<any> => {
  const names = await restrictedRecommendationNames(context, context.user as AuthUser, recommendation);
  const value = recommendation[field];
  return field === 'payload' || field === 'recommendation_evidence' ? maskRestrictedNamesInJson(value, names) : maskRestrictedNames(value, names);
};

const sourceIntelligenceResolvers: Resolvers = {
  Query: {
    sources: (_, args, context) => findSourcesPaginated(context, context.user, args) as any,
    source: (_, { id }, context) => findSourceById(context, context.user, id) as any,
    sourceScorecards: (_, args, context) => findSourceScorecards(context, context.user, args) as any,
    sourceOverlap: (_, args, context) => findSourceOverlap(context, context.user, args) as any,
    collectionGaps: (_, args, context) => findCollectionGaps(context, context.user, args) as any,
    sourceRecommendations: (_, args, context) => findRecommendationsPaginated(context, context.user, args) as any,
    sourceRecommendation: (_, { id }, context) => findRecommendationById(context, context.user, id) as any,
    sourceIntelligenceSettings: async (_, __, context) => ({
      ...(await getSourceIntelligenceSettings(context)),
      manager_running: await isSourceIntelligenceRunning(context),
      manager_enabled: await isSourceIntelligenceEnabled(),
    }) as any,
    sourceIntelligenceStatus: (_, __, context) => getSourceIntelligenceStatus(context) as any,
    sourceScorecardMetrics: () => SCORECARD_METRICS,
    sourceScorecardsDistribution: (_, args, context) => sourceScorecardsDistribution(context, context.user, args) as any,
    sourceScorecardsNumber: (_, args, context) => sourceScorecardsNumber(context, context.user, args),
    sourceScorecardsTimeSeries: (_, args, context) => sourceScorecardsTimeSeries(context, context.user, args),
    sourceScorecardsScatter: (_, args, context) => sourceScorecardsScatter(context, context.user, args) as any,
  },
  Source: {
    cost: (source: any) => source.source_cost ?? null,
    owner: (source: any, _, context) => (source.owner_id ? loadCreator(context, context.user, source.owner_id) : null),
    enabled: (source: any) => source.enabled !== false,
    quarantined: (source: any) => source.quarantined === true,
    latest_relevance: (source: any, _, context) => enterpriseValue(context, source.latest_relevance),
    connector: (source: any, _, context) => {
      if (!source.ref_id) return null;
      if (source.source_kind === SOURCE_KIND_CONNECTOR) return loadConnector(context, context.user, source.ref_id);
      if (source.source_kind === SOURCE_KIND_INGESTION_FEED) return loadConnector(context, context.user, connectorIdFromIngestId(source.ref_id));
      return null;
    },
    scorecard: (source: any, { period }, context) => findLatestScorecard(context, context.user, source.internal_id, period) as any,
    recommendationsCount: async (source: any, { status }, context) => {
      if (!(await isEnterpriseEdition(context))) return 0;
      return countRecommendations(context, context.user, source.internal_id, status && status.length > 0 ? status : ['proposed']);
    },
  },
  SourceScorecard: {
    period: (scorecard: any) => scorecard.scorecard_period,
    last_asserted_at: (scorecard: any) => scorecard.source_last_asserted_at ?? null,
    overlap: (scorecard: any) => scorecard.overlap ?? [],
    pir_matched_count: (scorecard: any, _, context) => enterpriseValue(context, scorecard.pir_matched_count),
    relevance: (scorecard: any, _, context) => enterpriseValue(context, scorecard.relevance),
  },
  SourceOverlapShare: {
    source: (share: any, _, context) => findSourceById(context, context.user, share.source_id) as any,
  },
  CollectionGap: {
    coverage_score: (gap: any) => gap.gap_coverage_score ?? 0,
    pir: (gap: any, _, context) => storeLoadById(context, context.user, gap.pir_id, ENTITY_TYPE_PIR) as any,
    covering_sources: (gap: any) => gap.covering_sources ?? [],
    recommended_connectors: (gap: any) => gap.recommended_connectors ?? [],
  },
  CollectionGapRecommendedConnector: {
    required_settings: (connector: any, _, context) => requiredSettingsOfImage(context, context.user as AuthUser, connector.contract_image),
  },
  CollectionGapCoveringSource: {
    source: (covering: any, _, context) => findSourceById(context, context.user, covering.source_id) as any,
  },
  SourceRecommendation: {
    name: (recommendation: any, _, context) => maskedRecommendationText(context, recommendation, 'name'),
    rationale: (recommendation: any, _, context) => maskedRecommendationText(context, recommendation, 'rationale'),
    payload: (recommendation: any, _, context) => maskedRecommendationText(context, recommendation, 'payload'),
    recommendation_evidence: (recommendation: any, _, context) => maskedRecommendationText(context, recommendation, 'recommendation_evidence'),
    apply_result: (recommendation: any, _, context) => maskedRecommendationText(context, recommendation, 'apply_result'),
    error_message: (recommendation: any, _, context) => maskedRecommendationText(context, recommendation, 'error_message'),
    dismiss_reason: (recommendation: any, _, context) => maskedRecommendationText(context, recommendation, 'dismiss_reason'),
    kind: (recommendation: any) => recommendation.recommendation_kind,
    status: (recommendation: any) => recommendation.recommendation_status,
    autonomous: (recommendation: any) => recommendation.autonomous === true,
    source: (recommendation: any, _, context) => (recommendation.source_id ? findSourceById(context, context.user, recommendation.source_id) as any : null),
    applied_by: (recommendation: any, _, context) => (recommendation.applied_by_id ? loadCreator(context, context.user, recommendation.applied_by_id) : null),
    reverted_by: (recommendation: any, _, context) => (recommendation.reverted_by_id ? loadCreator(context, context.user, recommendation.reverted_by_id) : null),
    dismissed_by: (recommendation: any, _, context) => (recommendation.dismissed_by_id ? loadCreator(context, context.user, recommendation.dismissed_by_id) : null),
    required_settings: (recommendation: any, _, context) => {
      if (recommendation.recommendation_kind !== RECOMMENDATION_ADD_CONNECTOR) return [];
      const image = parseJsonRecord(recommendation.payload).contract_image;
      return requiredSettingsOfImage(context, context.user as AuthUser, typeof image === 'string' ? image : null);
    },
  },
  Mutation: {
    sourceSetCost: (_, { id, input }, context) => sourceSetCost(context, context.user, id, input) as any,
    sourceFieldPatch: (_, { id, input }, context) => sourceEditField(context, context.user, id, input) as any,
    applySourceRecommendation: async (_, { id, input }, context) => {
      const settings = await getSourceIntelligenceSettings(context);
      return applySourceRecommendation(context, context.user, id, settings, input ?? {}) as any;
    },
    revertSourceRecommendation: (_, { id }, context) => revertSourceRecommendation(context, context.user, id) as any,
    dismissSourceRecommendation: (_, { id, reason }, context) => dismissSourceRecommendation(context, context.user, id, reason) as any,
    collectionGapDeployConnector: async (_, { id, slug, configuration }, context) => {
      const settings = await getSourceIntelligenceSettings(context);
      return deployCollectionGapConnector(context, context.user, id, slug, settings, configuration ?? []) as any;
    },
    sourceIntelligenceSettingsEdit: (_, { input }, context) => editSourceIntelligenceSettings(context, context.user, input) as any,
    sourceIntelligenceRecompute: (_, __, context) => requestSourceIntelligenceRecompute(context, context.user),
    sourceIntelligenceDashboardCreate: (_, { name }, context) => createIntelligenceRoiDashboard(context, context.user, name) as any,
  },
};

export default sourceIntelligenceResolvers;
