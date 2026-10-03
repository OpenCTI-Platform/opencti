import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, getUserIdByEmail, testContext, USER_CONNECTOR, USER_DISINFORMATION_ANALYST, USER_EDITOR } from '../../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithError, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../../utils/testQueryHelper';
import { runFullComputation } from '../../../../src/manager/sourceIntelligenceManager';
import { getSourceIntelligenceSettings, listAllSources } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-domain';
import { upsertProposals } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-recommendations';
import { deleteScorecardsOfSources } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-store';
import { type BasicStoreEntitySource, ENTITY_TYPE_SOURCE, ENTITY_TYPE_SOURCE_RECOMMENDATION } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';
import type { SourceIntelligenceSettings } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-settings';
import { deleteElementById } from '../../../../src/database/middleware';
import { fullEntitiesList, storeLoadById } from '../../../../src/database/middleware-loader';
import type { BasicStoreEntity } from '../../../../src/types/store';
import { deleteDraftWorkspace } from '../../../../src/modules/draftWorkspace/draftWorkspace-domain';
import { type BasicStoreEntityDraftWorkspace, ENTITY_TYPE_DRAFT_WORKSPACE } from '../../../../src/modules/draftWorkspace/draftWorkspace-types';
import { DRAFT_STATUS_OPEN } from '../../../../src/modules/draftWorkspace/draftStatuses';

const SOURCES_QUERY = gql`
  query sources($first: Int, $orderBy: SourcesOrdering, $orderMode: OrderingMode) {
    sources(first: $first, orderBy: $orderBy, orderMode: $orderMode) {
      edges {
        node {
          id
          name
          source_kind
          enabled
          quarantined
          last_computed_at
          latest_value_score
          latest_volume
        }
      }
    }
  }
`;

const SOURCE_QUERY = gql`
  query source($id: ID!) {
    source(id: $id) {
      id
      name
      cost {
        amount
        currency
        period
      }
      latest_cost_per_actionable
      scorecard(period: LAST_30_DAYS) {
        source_id
        period
        is_live
        volume_total
        unique_contribution
        corroboration_rate
        value_score
        cost_currency
        overlap {
          source_id
          shared_count
          share
        }
      }
    }
  }
`;

const SOURCE_SCORECARDS_QUERY = gql`
  query sourceScorecards($sourceId: ID!, $period: SourceScorecardPeriod) {
    sourceScorecards(sourceId: $sourceId, period: $period) {
      source_id
      period
      snapshot_date
      value_score
    }
  }
`;

const SOURCE_OVERLAP_QUERY = gql`
  query sourceOverlap($period: SourceScorecardPeriod, $first: Int) {
    sourceOverlap(period: $period, first: $first) {
      period
      sources {
        id
      }
      cells {
        source_a
        source_b
        shared_count
        share_a
        share_b
        jaccard
      }
    }
  }
`;

const STATUS_QUERY = gql`
  query sourceIntelligenceStatus {
    sourceIntelligenceStatus {
      enterprise_edition
      sources_count
      last_run_success
      last_scanned_objects
      provenance_mode
    }
  }
`;

const WIDGETS_QUERY = gql`
  query sourceWidgets($metric: String!) {
    sourceScorecardMetrics {
      key
      label
      type
      higher_is_better
      enterprise
    }
    sourceScorecardsNumber(metric: $metric, period: LAST_30_DAYS, aggregation: avg) {
      value
      sources_count
    }
    sourceScorecardsDistribution(metric: $metric, period: LAST_30_DAYS, first: 5, orderMode: desc) {
      label
      value
      entity {
        id
      }
    }
    sourceScorecardsTimeSeries(metric: "volume_total", period: LAST_30_DAYS, aggregation: sum) {
      date
      value
    }
    sourceScorecardsScatter(xMetric: "volume_total", yMetric: $metric, period: LAST_30_DAYS, first: 10) {
      label
      x
      y
    }
  }
`;

const COLLECTION_GAPS_QUERY = gql`
  query collectionGaps {
    collectionGaps(first: 50) {
      edges {
        node {
          id
          pir_id
          coverage_score
          is_gap
        }
      }
    }
  }
`;

const SET_COST_MUTATION = gql`
  mutation sourceSetCost($id: ID!, $input: SourceCostInput) {
    sourceSetCost(id: $id, input: $input) {
      id
      cost {
        amount
        currency
        period
      }
    }
  }
`;

const SETTINGS_QUERY = gql`
  query sourceIntelligenceSettings {
    sourceIntelligenceSettings {
      overlap_top
      backfill_days
    }
  }
`;

const SETTINGS_EDIT_MUTATION = gql`
  mutation sourceIntelligenceSettingsEdit($input: SourceIntelligenceSettingsInput!) {
    sourceIntelligenceSettingsEdit(input: $input) {
      overlap_top
      backfill_days
    }
  }
`;

const RECOMMENDATIONS_QUERY = gql`
  query sourceRecommendations($status: [SourceRecommendationStatus!], $kind: [SourceRecommendationKind!]) {
    sourceRecommendations(first: 100, status: $status, kind: $kind) {
      edges {
        node {
          id
          name
          kind
          status
        }
      }
    }
  }
`;

const APPLY_MUTATION = gql`
  mutation applySourceRecommendation($id: ID!) {
    applySourceRecommendation(id: $id) {
      id
      status
      apply_result
      applied_at
      applied_by {
        id
      }
    }
  }
`;

const DEPLOY_MUTATION = gql`
  mutation collectionGapDeployConnector($id: ID!, $slug: String!) {
    collectionGapDeployConnector(id: $id, slug: $slug) {
      id
      status
    }
  }
`;

const REVERT_MUTATION = gql`
  mutation revertSourceRecommendation($id: ID!) {
    revertSourceRecommendation(id: $id) {
      id
      status
      reverted_at
    }
  }
`;

const DISMISS_MUTATION = gql`
  mutation dismissSourceRecommendation($id: ID!, $reason: String) {
    dismissSourceRecommendation(id: $id, reason: $reason) {
      id
      status
      dismiss_reason
    }
  }
`;

const USER_CONFIDENCE_QUERY = gql`
  query user($id: String!) {
    user(id: $id) {
      id
      user_confidence_level {
        max_confidence
      }
    }
  }
`;

const DASHBOARD_CREATE_MUTATION = gql`
  mutation sourceIntelligenceDashboardCreate($name: String) {
    sourceIntelligenceDashboardCreate(name: $name) {
      id
      name
      type
      manifest
    }
  }
`;

const WORKSPACE_DELETE_MUTATION = gql`
  mutation workspaceDelete($id: ID!) {
    workspaceDelete(id: $id)
  }
`;

const TEST_FINGERPRINT_PREFIX = 'integration-test-source-intelligence';

describe('Source intelligence', () => {
  let settings: SourceIntelligenceSettings;
  let sourceId: string;
  let connectorUserId: string;
  let previousMaxConfidence: number | null = null;

  beforeAll(async () => {
    settings = await getSourceIntelligenceSettings(testContext);
    // The test dataset is small: lower the discovery thresholds so authors and analysts become sources
    await runFullComputation(testContext, { ...settings, min_author_volume: 1, min_manual_volume: 1, backfill_days: 0 });
    connectorUserId = await getUserIdByEmail(USER_CONNECTOR.email) as string;
    expect(connectorUserId).toBeTruthy();
  }, 240000);

  afterAll(async () => {
    const recommendations = await fullEntitiesList<BasicStoreEntity & { fingerprint: string }>(testContext, ADMIN_USER, [ENTITY_TYPE_SOURCE_RECOMMENDATION]);
    for (let i = 0; i < recommendations.length; i += 1) {
      await deleteElementById(testContext, ADMIN_USER, recommendations[i].internal_id, ENTITY_TYPE_SOURCE_RECOMMENDATION);
    }
    const sources = await listAllSources(testContext);
    for (let i = 0; i < sources.length; i += 1) {
      await deleteElementById(testContext, ADMIN_USER, sources[i].internal_id, ENTITY_TYPE_SOURCE);
    }
    await deleteScorecardsOfSources(testContext, sources.map((source) => source.internal_id));
  });

  it('should materialize and score sources from the platform knowledge', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: SOURCES_QUERY, variables: { first: 100, orderBy: 'latest_value_score', orderMode: 'desc' } });
    const sources = data.sources.edges.map((edge: { node: any }) => edge.node);
    expect(sources.length).toBeGreaterThan(0);
    const scored = sources.filter((source: any) => source.last_computed_at);
    expect(scored.length).toBeGreaterThan(0);
    scored.forEach((source: any) => {
      expect(source.latest_value_score).toBeGreaterThanOrEqual(0);
      expect(source.latest_value_score).toBeLessThanOrEqual(100);
      expect(source.enabled).toBe(true);
      expect(source.quarantined).toBe(false);
    });
    const withVolume = scored.find((source: any) => (source.latest_volume ?? 0) > 0) ?? scored[0];
    sourceId = withVolume.id;
  });

  it('should expose the live scorecard and the history of a source', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: SOURCE_QUERY, variables: { id: sourceId } });
    const { scorecard } = data.source;
    expect(scorecard).not.toBeNull();
    expect(scorecard.source_id).toBe(sourceId);
    expect(scorecard.period).toBe('LAST_30_DAYS');
    expect(scorecard.is_live).toBe(true);
    expect(scorecard.unique_contribution).toBeGreaterThanOrEqual(0);
    expect(scorecard.unique_contribution).toBeLessThanOrEqual(1);
    expect(scorecard.corroboration_rate).toBeGreaterThanOrEqual(0);
    expect(scorecard.corroboration_rate).toBeLessThanOrEqual(1);
    scorecard.overlap.forEach((share: { source_id: string; share: number }) => {
      expect(share.source_id).not.toBe(sourceId);
      expect(share.share).toBeGreaterThanOrEqual(0);
      expect(share.share).toBeLessThanOrEqual(1);
    });
    const history = await queryAsAdminWithSuccess({ query: SOURCE_SCORECARDS_QUERY, variables: { sourceId, period: 'LAST_30_DAYS' } });
    expect(history.data.sourceScorecards.length).toBeGreaterThan(0);
    history.data.sourceScorecards.forEach((point: { source_id: string }) => expect(point.source_id).toBe(sourceId));
  });

  it('should return no scorecard for an unknown source', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: SOURCE_SCORECARDS_QUERY, variables: { sourceId: 'source--00000000-0000-4000-8000-000000000000' } });
    expect(data.sourceScorecards).toEqual([]);
  });

  it('should compute a consistent overlap matrix', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: SOURCE_OVERLAP_QUERY, variables: { period: 'LAST_30_DAYS', first: 20 } });
    const matrix = data.sourceOverlap;
    expect(matrix.period).toBe('LAST_30_DAYS');
    const ids = new Set(matrix.sources.map((source: { id: string }) => source.id));
    matrix.cells.forEach((cell: any) => {
      expect(ids.has(cell.source_a)).toBe(true);
      expect(ids.has(cell.source_b)).toBe(true);
      expect(cell.source_a).not.toBe(cell.source_b);
      expect(cell.shared_count).toBeGreaterThan(0);
      [cell.share_a, cell.share_b, cell.jaccard].forEach((ratio: number) => {
        expect(ratio).toBeGreaterThanOrEqual(0);
        expect(ratio).toBeLessThanOrEqual(1);
      });
    });
  });

  it('should report the computation status', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: STATUS_QUERY });
    const status = data.sourceIntelligenceStatus;
    expect(status.last_run_success).toBe(true);
    expect(status.sources_count).toBeGreaterThan(0);
    expect(status.last_scanned_objects).toBeGreaterThan(0);
    expect(['assertions', 'creators']).toContain(status.provenance_mode);
  });

  it('should serve the dashboard widgets of the sources perspective', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: WIDGETS_QUERY, variables: { metric: 'value_score' } });
    expect(data.sourceScorecardMetrics.map((metric: { key: string }) => metric.key)).toContain('value_score');
    expect(data.sourceScorecardsNumber.sources_count).toBeGreaterThan(0);
    expect(data.sourceScorecardsNumber.value).toBeGreaterThanOrEqual(0);
    expect(data.sourceScorecardsNumber.value).toBeLessThanOrEqual(100);
    const distribution = data.sourceScorecardsDistribution;
    expect(distribution.length).toBeGreaterThan(0);
    expect(distribution.length).toBeLessThanOrEqual(5);
    for (let i = 1; i < distribution.length; i += 1) {
      expect(distribution[i - 1].value).toBeGreaterThanOrEqual(distribution[i].value);
    }
    expect(Array.isArray(data.sourceScorecardsTimeSeries)).toBe(true);
    expect(data.sourceScorecardsScatter.length).toBeLessThanOrEqual(10);
  });

  it('should reject an unknown widget metric', async () => {
    const result = await queryAsAdmin({ query: WIDGETS_QUERY, variables: { metric: 'not_a_metric' } });
    expect(result.errors?.length).toBeGreaterThan(0);
  });

  it('should list collection gaps with bounded coverage scores', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: COLLECTION_GAPS_QUERY });
    data.collectionGaps.edges.forEach(({ node }: { node: any }) => {
      expect(node.pir_id).toBeTruthy();
      expect(node.coverage_score).toBeGreaterThanOrEqual(0);
      expect(node.coverage_score).toBeLessThanOrEqual(100);
    });
  });

  it('should set, validate and clear the cost of a source', async () => {
    const set = await queryAsAdminWithSuccess({ query: SET_COST_MUTATION, variables: { id: sourceId, input: { amount: 12000, currency: 'eur', period: 'year' } } });
    expect(set.data.sourceSetCost.cost).toEqual({ amount: 12000, currency: 'EUR', period: 'year' });
    const { data } = await queryAsAdminWithSuccess({ query: SOURCE_QUERY, variables: { id: sourceId } });
    expect(data.source.scorecard.cost_currency).toBe('EUR');
    await queryAsAdminWithError(
      { query: SET_COST_MUTATION, variables: { id: sourceId, input: { amount: 10, currency: 'E1R', period: 'year' } } },
      'Invalid source cost currency, an ISO 4217 code is expected',
    );
    await queryAsAdminWithError(
      { query: SET_COST_MUTATION, variables: { id: sourceId, input: { amount: -1, currency: 'EUR', period: 'year' } } },
      'Invalid source cost amount',
    );
    const cleared = await queryAsAdminWithSuccess({ query: SET_COST_MUTATION, variables: { id: sourceId, input: null } });
    expect(cleared.data.sourceSetCost.cost).toBeNull();
  });

  it('should validate and persist the settings', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: SETTINGS_QUERY });
    const initialOverlapTop = data.sourceIntelligenceSettings.overlap_top;
    await queryAsAdminWithError(
      { query: SETTINGS_EDIT_MUTATION, variables: { input: { backfill_days: 1000 } } },
      'Invalid source intelligence setting, value out of bounds',
    );
    const nextOverlapTop = initialOverlapTop === 15 ? 16 : 15;
    const edited = await queryAsAdminWithSuccess({ query: SETTINGS_EDIT_MUTATION, variables: { input: { overlap_top: nextOverlapTop } } });
    expect(edited.data.sourceIntelligenceSettingsEdit.overlap_top).toBe(nextOverlapTop);
    const restored = await queryAsAdminWithSuccess({ query: SETTINGS_EDIT_MUTATION, variables: { input: { overlap_top: initialOverlapTop } } });
    expect(restored.data.sourceIntelligenceSettingsEdit.overlap_top).toBe(initialOverlapTop);
  });

  it('should apply and revert a confidence recommendation with an audit trail', async () => {
    const before = await queryAsAdminWithSuccess({ query: USER_CONFIDENCE_QUERY, variables: { id: connectorUserId } });
    previousMaxConfidence = before.data.user.user_confidence_level?.max_confidence ?? null;
    const proposedMaxConfidence = previousMaxConfidence === 40 ? 45 : 40;
    const { created } = await upsertProposals(testContext, [{
      kind: 'lower_confidence',
      source_id: sourceId,
      fingerprint: `${TEST_FINGERPRINT_PREFIX}-confidence`,
      name: 'Lower the confidence of the test connector',
      rationale: 'Integration test',
      payload: { user_id: connectorUserId, proposed_max_confidence: proposedMaxConfidence },
      evidence: {},
    }], settings, { kinds: [] });
    expect(created.length).toBe(1);
    const recommendationId = created[0].internal_id;

    const applied = await queryAsAdminWithSuccess({ query: APPLY_MUTATION, variables: { id: recommendationId } });
    expect(applied.data.applySourceRecommendation.status).toBe('applied');
    expect(applied.data.applySourceRecommendation.applied_at).toBeTruthy();
    expect(applied.data.applySourceRecommendation.applied_by.id).toBe(ADMIN_USER.id);
    const during = await queryAsAdminWithSuccess({ query: USER_CONFIDENCE_QUERY, variables: { id: connectorUserId } });
    expect(during.data.user.user_confidence_level.max_confidence).toBe(proposedMaxConfidence);

    await queryAsAdminWithError({ query: APPLY_MUTATION, variables: { id: recommendationId } }, 'Only proposed recommendations can be applied');

    const reverted = await queryAsAdminWithSuccess({ query: REVERT_MUTATION, variables: { id: recommendationId } });
    expect(reverted.data.revertSourceRecommendation.status).toBe('reverted');
    const after = await queryAsAdminWithSuccess({ query: USER_CONFIDENCE_QUERY, variables: { id: connectorUserId } });
    expect(after.data.user.user_confidence_level?.max_confidence ?? null).toBe(previousMaxConfidence);
  });

  it('should open a new quarantine draft when the current one is deleted', async () => {
    // A source without connector user: the quarantine is carried by the draft only, no real user changes context
    const { data } = await queryAsAdminWithSuccess({ query: SOURCES_QUERY, variables: { first: 100 } });
    const target = data.sources.edges.map((edge: { node: any }) => edge.node).find((source: any) => source.source_kind !== 'connector');
    expect(target).toBeDefined();
    const { created } = await upsertProposals(testContext, [{
      kind: 'quarantine',
      source_id: target.id,
      fingerprint: `${TEST_FINGERPRINT_PREFIX}-quarantine`,
      name: 'Quarantine the test source into a draft',
      rationale: 'Integration test',
      payload: { target: 'ingestion_feed' },
      evidence: {},
    }], settings, { kinds: [] });
    expect(created.length).toBe(1);
    const recommendationId = created[0].internal_id;
    const applied = await queryAsAdminWithSuccess({ query: APPLY_MUTATION, variables: { id: recommendationId } });
    expect(applied.data.applySourceRecommendation.status).toBe('applied');
    const quarantined = await storeLoadById<BasicStoreEntitySource>(testContext, ADMIN_USER, target.id, ENTITY_TYPE_SOURCE);
    expect(quarantined?.quarantined).toBe(true);
    const firstDraftId = quarantined?.quarantine_draft_id as string;
    expect(firstDraftId).toBeTruthy();

    await deleteDraftWorkspace(testContext, ADMIN_USER, firstDraftId);
    const renewed = await storeLoadById<BasicStoreEntitySource>(testContext, ADMIN_USER, target.id, ENTITY_TYPE_SOURCE);
    expect(renewed?.quarantined).toBe(true);
    const renewedDraftId = renewed?.quarantine_draft_id as string;
    expect(renewedDraftId).toBeTruthy();
    expect(renewedDraftId).not.toBe(firstDraftId);
    const renewedDraft = await storeLoadById<BasicStoreEntityDraftWorkspace>(testContext, ADMIN_USER, renewedDraftId, ENTITY_TYPE_DRAFT_WORKSPACE);
    expect(renewedDraft?.draft_status).toBe(DRAFT_STATUS_OPEN);

    const reverted = await queryAsAdminWithSuccess({ query: REVERT_MUTATION, variables: { id: recommendationId } });
    expect(reverted.data.revertSourceRecommendation.status).toBe('reverted');
    const lifted = await storeLoadById<BasicStoreEntitySource>(testContext, ADMIN_USER, target.id, ENTITY_TYPE_SOURCE);
    expect(lifted?.quarantined).toBe(false);
    expect(lifted?.quarantine_draft_id ?? null).toBeNull();
    await deleteDraftWorkspace(testContext, ADMIN_USER, renewedDraftId);
  });

  it('should dismiss a recommendation and not propose it again during the cooldown', async () => {
    const proposal = {
      kind: 'raise_confidence' as const,
      source_id: sourceId,
      fingerprint: `${TEST_FINGERPRINT_PREFIX}-dismiss`,
      name: 'Raise the confidence of the test connector',
      rationale: 'Integration test',
      payload: { user_id: connectorUserId, proposed_max_confidence: 90 },
      evidence: {},
    };
    const { created } = await upsertProposals(testContext, [proposal], settings, { kinds: [] });
    expect(created.length).toBe(1);
    const recommendationId = created[0].internal_id;
    const dismissed = await queryAsAdminWithSuccess({ query: DISMISS_MUTATION, variables: { id: recommendationId, reason: 'Known trusted feed' } });
    expect(dismissed.data.dismissSourceRecommendation.status).toBe('dismissed');
    expect(dismissed.data.dismissSourceRecommendation.dismiss_reason).toBe('Known trusted feed');
    await queryAsAdminWithError({ query: REVERT_MUTATION, variables: { id: recommendationId } }, 'Only applied recommendations can be reverted');
    const again = await upsertProposals(testContext, [proposal], settings, { kinds: [] });
    expect(again.created.length).toBe(0);
    const { data } = await queryAsAdminWithSuccess({ query: RECOMMENDATIONS_QUERY, variables: { status: ['dismissed'], kind: ['raise_confidence'] } });
    expect(data.sourceRecommendations.edges.map(({ node }: { node: { id: string } }) => node.id)).toContain(recommendationId);
  });

  it('should create the Intelligence ROI dashboard', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: DASHBOARD_CREATE_MUTATION, variables: { name: 'Intelligence ROI (test)' } });
    const workspace = data.sourceIntelligenceDashboardCreate;
    expect(workspace.name).toBe('Intelligence ROI (test)');
    expect(workspace.type).toBe('dashboard');
    const manifest = JSON.parse(Buffer.from(workspace.manifest, 'base64').toString('utf-8'));
    const perspectives = Object.values(manifest.widgets).map((widget: any) => widget.perspective);
    expect(perspectives.length).toBeGreaterThan(0);
    expect(perspectives.every((perspective) => perspective === 'sources')).toBe(true);
    await queryAsAdminWithSuccess({ query: WORKSPACE_DELETE_MUTATION, variables: { id: workspace.id } });
  });

  it('should restrict sources to users with the ingestion or connectors capabilities', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: SOURCES_QUERY, variables: { first: 5 } });
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: SET_COST_MUTATION, variables: { id: sourceId, input: null } });
    const { data } = await queryAsUserWithSuccess(USER_DISINFORMATION_ANALYST, { query: SOURCES_QUERY, variables: { first: 5 } });
    expect(data.sources.edges.length).toBeGreaterThan(0);
  });

  it('should require the access management capability to apply a confidence recommendation', async () => {
    const { created } = await upsertProposals(testContext, [{
      kind: 'raise_confidence',
      source_id: sourceId,
      fingerprint: `${TEST_FINGERPRINT_PREFIX}-rbac`,
      name: 'Raise the confidence of the test connector (RBAC)',
      rationale: 'Integration test',
      payload: { user_id: connectorUserId, proposed_max_confidence: 80 },
      evidence: {},
    }], settings, { kinds: [] });
    await queryAsUserIsExpectedForbidden(USER_DISINFORMATION_ANALYST, { query: APPLY_MUTATION, variables: { id: created[0].internal_id } });
  });

  it('should guard the one-click deployment of a collection gap connector', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: DEPLOY_MUTATION, variables: { id: sourceId, slug: 'any-connector' } });
    const unknownGap = await queryAsAdmin({ query: DEPLOY_MUTATION, variables: { id: sourceId, slug: 'any-connector' } });
    expect(unknownGap.errors?.[0]?.message).toEqual('Collection gap not found');
  });
});
