import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, getUserIdByEmail, testContext, USER_CONNECTOR, USER_DISINFORMATION_ANALYST, USER_EDITOR } from '../../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithError, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../../utils/testQueryHelper';
import { runFullComputation } from '../../../../src/manager/sourceIntelligenceManager';
import { getSourceIntelligenceSettings, listAllSources, syncSources, writeComputedSourceKpis } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-domain';
import { findOrCreateProposal, findRecommendationsByFingerprint, upsertProposals } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-recommendations';
import {
  applyLiveScorecardCost,
  deleteScorecardsOfSources,
  findLiveScorecards,
  searchScorecards,
  writeScorecards,
} from '../../../../src/modules/sourceIntelligence/sourceIntelligence-store';
import { computeCostPerActionable } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-scoring';
import { type RecommendationProposal, recommendationFingerprint } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-rules';
import {
  type BasicStoreEntitySource,
  type BasicStoreEntitySourceRecommendation,
  ENTITY_TYPE_SOURCE,
  ENTITY_TYPE_SOURCE_RECOMMENDATION,
  ENTITY_TYPE_SOURCE_SCORECARD,
  RECOMMENDATION_LOWER_CONFIDENCE,
  RECOMMENDATION_RETIRE,
  REFERENCE_SCORECARD_PERIOD,
  SCORECARD_PERIOD_DAYS,
  SCORECARD_PERIODS,
} from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';
import type { SourceIntelligenceSettings } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-settings';
import { v4 as uuidv4 } from 'uuid';
import { createEntity, deleteElementById, patchAttribute } from '../../../../src/database/middleware';
import { elUpdate } from '../../../../src/database/engine';
import { resolveFeedQuarantineDraftId } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-quarantine';
import { fullEntitiesList, storeLoadById } from '../../../../src/database/middleware-loader';
import type { BasicStoreEntity } from '../../../../src/types/store';
import { addDraftWorkspace, deleteDraftWorkspace } from '../../../../src/modules/draftWorkspace/draftWorkspace-domain';
import { userEditField } from '../../../../src/modules/user/user-domain';
import { ENTITY_TYPE_USER } from '../../../../src/schema/internalObject';
import { type BasicStoreEntityDraftWorkspace, ENTITY_TYPE_DRAFT_WORKSPACE } from '../../../../src/modules/draftWorkspace/draftWorkspace-types';
import { DRAFT_STATUS_OPEN } from '../../../../src/modules/draftWorkspace/draftStatuses';
import { resolveDraftForward } from '../../../../src/modules/draftWorkspace/draftWorkspace-closure';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import { ENTITY_TYPE_MALWARE } from '../../../../src/schema/stixDomainObject';

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
      scorecard_date
      is_live
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
      scored_sources_count
      last_run_success
      last_scanned_objects
      last_scan_truncated
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
      currency
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

  it('should mark the live scorecards with the stream boundary of the full computation', async () => {
    const live = await findLiveScorecards(testContext, REFERENCE_SCORECARD_PERIOD);
    expect(live.length).toBeGreaterThan(0);
    // Every live scorecard counts the events written before the scan: a replayed stream batch up to it is a no-op
    const boundary = live[0].live_stream_event_id;
    expect(boundary).toMatch(/^\d+-\d+$/);
    live.forEach((scorecard) => expect(scorecard.live_stream_event_id).toEqual(boundary));
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
    // The snapshots, then the live scorecard carrying the increments since the last snapshot
    const points = history.data.sourceScorecards as Array<{ is_live: boolean }>;
    expect(points.filter((point) => point.is_live)).toHaveLength(1);
    expect(points[points.length - 1].is_live).toBe(true);
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
    // Only the sources whose scorecards count knowledge are scored, never more than the sources tracked
    expect(status.scored_sources_count).toBeGreaterThan(0);
    expect(status.scored_sources_count).toBeLessThanOrEqual(status.sources_count);
    expect(status.last_scanned_objects).toBeGreaterThan(0);
  });

  it('should serve the dashboard widgets of the sources perspective', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: WIDGETS_QUERY, variables: { metric: 'value_score' } });
    expect(data.sourceScorecardMetrics.map((metric: { key: string }) => metric.key)).toContain('value_score');
    expect(data.sourceScorecardsNumber.sources_count).toBeGreaterThan(0);
    // Only cost metrics carry a currency
    expect(data.sourceScorecardsNumber.currency).toBeNull();
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

  it('should write the latest KPIs of a source with the cost it has when they are saved', async () => {
    const computed = await storeLoadById<BasicStoreEntitySource>(testContext, ADMIN_USER, sourceId, ENTITY_TYPE_SOURCE) as BasicStoreEntitySource;
    expect(computed.source_cost ?? null).toBeNull();
    const [reference] = await findLiveScorecards(testContext, REFERENCE_SCORECARD_PERIOD, [sourceId]);
    expect(reference).toBeDefined();
    // A cost is set while the computation runs, then the computation writes the scorecards it built without a cost
    await queryAsAdminWithSuccess({ query: SET_COST_MUTATION, variables: { id: sourceId, input: { amount: 3000, currency: 'USD', period: 'month' } } });
    await applyLiveScorecardCost(testContext, sourceId, null, new Map(SCORECARD_PERIODS.map((period) => [period, null])));
    expect(await writeComputedSourceKpis(testContext, computed, reference, { latest_value_score: reference.value_score })).toBe(true);
    const [rewritten] = await findLiveScorecards(testContext, REFERENCE_SCORECARD_PERIOD, [sourceId]);
    expect(rewritten.cost_currency).toBe('USD');
    const source = await storeLoadById<BasicStoreEntitySource>(testContext, ADMIN_USER, sourceId, ENTITY_TYPE_SOURCE) as BasicStoreEntitySource;
    const expected = computeCostPerActionable({ amount: 3000, currency: 'USD', period: 'month' }, SCORECARD_PERIOD_DAYS[REFERENCE_SCORECARD_PERIOD], reference.actionable_count);
    expect(source.latest_cost_per_actionable ?? null).toBe(expected);
    expect(rewritten.cost_per_actionable_object ?? null).toBe(expected);
    await queryAsAdminWithSuccess({ query: SET_COST_MUTATION, variables: { id: sourceId, input: null } });
  });

  it('should remove the authors and analysts that left the discovery unless they are curated', async () => {
    const createAuthorSource = (name: string, extra: Record<string, unknown> = {}) => createEntity(testContext, ADMIN_USER, {
      source_kind: 'author',
      ref_id: uuidv4(),
      ref_type: 'Organization',
      name,
      source_user_ids: [],
      enabled: true,
      quarantined: false,
      ...extra,
    }, ENTITY_TYPE_SOURCE);
    // Neither author wrote anything: both are out of the discovery
    const departed = await createAuthorSource('Source intelligence departed author');
    const curated = await createAuthorSource('Source intelligence curated author', { tags: ['reviewed'] });
    await syncSources(testContext, { ...settings, min_author_volume: 1, min_manual_volume: 1 });
    expect(await storeLoadById(testContext, ADMIN_USER, departed.internal_id, ENTITY_TYPE_SOURCE)).toBeFalsy();
    expect(await storeLoadById(testContext, ADMIN_USER, curated.internal_id, ENTITY_TYPE_SOURCE)).toBeTruthy();
    // The discovered sources are untouched
    expect(await storeLoadById(testContext, ADMIN_USER, sourceId, ENTITY_TYPE_SOURCE)).toBeTruthy();
    await deleteElementById(testContext, ADMIN_USER, curated.internal_id, ENTITY_TYPE_SOURCE);
  });

  it('should discover an author of knowledge written during the window, and only then', async () => {
    const author = await createEntity(testContext, ADMIN_USER, { name: 'Source intelligence writing author' }, ENTITY_TYPE_IDENTITY_ORGANIZATION);
    const authored = await createEntity(testContext, ADMIN_USER, { name: 'Source intelligence authored malware', is_family: false, createdBy: author.internal_id }, ENTITY_TYPE_MALWARE);
    const discoveredAuthor = async () => {
      await syncSources(testContext, { ...settings, min_author_volume: 1, min_manual_volume: 1, max_author_sources: 10000 });
      return (await listAllSources(testContext)).find((source) => source.source_kind === 'author' && source.ref_id === author.internal_id);
    };
    expect(await discoveredAuthor()).toBeTruthy();
    // Last written before the longest period: the author left the discovery and, not curated, is removed
    const stored = await storeLoadById(testContext, ADMIN_USER, authored.internal_id, ENTITY_TYPE_MALWARE);
    await elUpdate(testContext, stored?._index as string, authored.internal_id, { doc: { updated_at: '2020-01-01T00:00:00.000Z' } });
    expect(await discoveredAuthor()).toBeFalsy();
    await deleteElementById(testContext, ADMIN_USER, authored.internal_id, ENTITY_TYPE_MALWARE);
    await deleteElementById(testContext, ADMIN_USER, author.internal_id, ENTITY_TYPE_IDENTITY_ORGANIZATION);
  });

  it('should give the connector user its draft context back when a quarantined connector source is removed', async () => {
    const draft = await addDraftWorkspace(testContext, ADMIN_USER, { name: 'Source intelligence orphan quarantine draft' });
    // A connector deleted from the platform while its source was quarantined: its service account stays
    const orphan = await createEntity(testContext, ADMIN_USER, {
      source_kind: 'connector',
      ref_id: uuidv4(),
      ref_type: 'Connector',
      name: 'Source intelligence deleted quarantined connector',
      source_user_ids: [connectorUserId],
      enabled: true,
      quarantined: true,
      quarantine_draft_id: draft.id,
    }, ENTITY_TYPE_SOURCE);
    const { created } = await upsertProposals(testContext, [{
      kind: 'quarantine',
      source_id: orphan.internal_id,
      fingerprint: `${TEST_FINGERPRINT_PREFIX}-orphan-quarantine`,
      name: 'Quarantine the deleted connector',
      rationale: 'Integration test',
      payload: { target: 'connector_user', user_id: connectorUserId },
      evidence: {},
    }], settings, { kinds: [] });
    await patchAttribute(testContext, ADMIN_USER, created[0].internal_id, ENTITY_TYPE_SOURCE_RECOMMENDATION, {
      recommendation_status: 'applied',
      revert_payload: JSON.stringify({ target: 'connector_user', user_id: connectorUserId, previous_draft_context: '', draft_id: draft.id }),
    });
    await userEditField(testContext, ADMIN_USER, connectorUserId, [{ key: 'draft_context', value: [draft.id] }]);
    try {
      await syncSources(testContext, { ...settings, min_author_volume: 1, min_manual_volume: 1 });
      expect(await storeLoadById(testContext, ADMIN_USER, orphan.internal_id, ENTITY_TYPE_SOURCE)).toBeFalsy();
      const connectorUser = await storeLoadById<BasicStoreEntity & { draft_context?: string | null }>(testContext, ADMIN_USER, connectorUserId, ENTITY_TYPE_USER);
      expect(connectorUser?.draft_context ?? '').toBe('');
    } finally {
      await userEditField(testContext, ADMIN_USER, connectorUserId, [{ key: 'draft_context', value: [''] }]);
      await deleteElementById(testContext, ADMIN_USER, created[0].internal_id, ENTITY_TYPE_SOURCE_RECOMMENDATION);
      await deleteDraftWorkspace(testContext, ADMIN_USER, draft.id);
    }
  });

  it('should hand the recommendations, curation and history of a duplicate analyst source over to the kept one', async () => {
    // Two analyst sources of one user, as a user merge leaves them: the one created for the other user now references
    // the kept user too, while its identity still comes from the user it was created for
    const refId = uuidv4();
    const createAnalystSource = (name: string, ref: string, extra: Record<string, unknown> = {}) => createEntity(testContext, ADMIN_USER, {
      source_kind: 'manual',
      ref_id: ref,
      ref_type: 'User',
      name,
      source_user_ids: [],
      enabled: true,
      quarantined: false,
      ...extra,
    }, ENTITY_TYPE_SOURCE);
    const kept = await createAnalystSource('Source intelligence merged analyst', refId);
    const duplicate = await createAnalystSource('Source intelligence merged analyst (duplicate)', uuidv4(), { tags: ['reviewed'] });
    const stored = await storeLoadById<BasicStoreEntitySource>(testContext, ADMIN_USER, duplicate.internal_id, ENTITY_TYPE_SOURCE);
    await elUpdate(testContext, stored?._index as string, duplicate.internal_id, { doc: { ref_id: refId } });
    const { created } = await upsertProposals(testContext, [{
      kind: 'retire',
      source_id: duplicate.internal_id,
      fingerprint: recommendationFingerprint(RECOMMENDATION_RETIRE, duplicate.internal_id),
      name: 'Retire the duplicate analyst source',
      rationale: 'Integration test',
      payload: { target: 'source' },
      evidence: {},
    }], settings, { kinds: [] });
    // The same pending recommendation on both sources: the kept one stays the only live entry of its fingerprint
    const lowerConfidence = (sourceId: string): RecommendationProposal => ({
      kind: RECOMMENDATION_LOWER_CONFIDENCE,
      source_id: sourceId,
      fingerprint: recommendationFingerprint(RECOMMENDATION_LOWER_CONFIDENCE, sourceId),
      name: 'Lower the confidence of the analyst source',
      rationale: 'Integration test',
      payload: { target: 'source' },
      evidence: {},
    });
    const { created: pending } = await upsertProposals(testContext, [lowerConfidence(duplicate.internal_id), lowerConfidence(kept.internal_id)], settings, { kinds: [] });
    expect(pending.length).toBe(2);
    await patchAttribute(testContext, ADMIN_USER, created[0].internal_id, ENTITY_TYPE_SOURCE_RECOMMENDATION, {
      recommendation_status: 'applied',
      revert_payload: JSON.stringify({ target: 'source', source_id: duplicate.internal_id, previous_enabled: true }),
    });
    const snapshotId = `${duplicate.internal_id}--${REFERENCE_SCORECARD_PERIOD}--2026-01-01`;
    await writeScorecards(testContext, [{
      id: snapshotId,
      internal_id: snapshotId,
      standard_id: `source-scorecard--${snapshotId}`,
      entity_type: ENTITY_TYPE_SOURCE_SCORECARD,
      source_id: duplicate.internal_id,
      scorecard_period: REFERENCE_SCORECARD_PERIOD,
      scorecard_date: '2026-01-01',
      computed_at: '2026-01-01T23:59:59.999Z',
      is_live: false,
      volume_total: 3,
      overlap: [],
    } as any]);

    await syncSources(testContext, { ...settings, min_author_volume: 1, min_manual_volume: 1 });

    expect(await storeLoadById(testContext, ADMIN_USER, duplicate.internal_id, ENTITY_TYPE_SOURCE)).toBeFalsy();
    const merged = await storeLoadById<BasicStoreEntitySource>(testContext, ADMIN_USER, kept.internal_id, ENTITY_TYPE_SOURCE);
    expect(merged?.tags).toEqual(['reviewed']);
    const loadRecommendation = (id: string) => storeLoadById<BasicStoreEntitySourceRecommendation>(testContext, ADMIN_USER, id, ENTITY_TYPE_SOURCE_RECOMMENDATION);
    const recommendation = await loadRecommendation(created[0].internal_id);
    expect(recommendation?.source_id).toBe(kept.internal_id);
    expect(recommendation?.fingerprint).toBe(recommendationFingerprint(RECOMMENDATION_RETIRE, kept.internal_id));
    expect(JSON.parse(recommendation?.revert_payload ?? '{}').source_id).toBe(kept.internal_id);
    const [movedPending, keptPending] = await Promise.all(pending.map((proposal) => loadRecommendation(proposal.internal_id)));
    expect(movedPending?.fingerprint).toBe(recommendationFingerprint(RECOMMENDATION_LOWER_CONFIDENCE, kept.internal_id));
    expect(movedPending?.recommendation_status).toBe('dismissed');
    expect(keptPending?.recommendation_status).toBe('proposed');
    const history = await searchScorecards(testContext, { sourceIds: [kept.internal_id], live: false });
    expect(history.map((scorecard) => scorecard.scorecard_date)).toContain('2026-01-01');
    const recommendationIds = [created[0], ...pending].map((proposal) => proposal.internal_id);
    for (let i = 0; i < recommendationIds.length; i += 1) {
      await deleteElementById(testContext, ADMIN_USER, recommendationIds[i], ENTITY_TYPE_SOURCE_RECOMMENDATION);
    }
    await deleteElementById(testContext, ADMIN_USER, kept.internal_id, ENTITY_TYPE_SOURCE);
    await deleteScorecardsOfSources(testContext, [kept.internal_id]);
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

  it('should require the customization capability to edit the settings', async () => {
    // Reading sources does not grant changing thresholds or the autonomy allow-list
    await queryAsUserWithSuccess(USER_DISINFORMATION_ANALYST, { query: SOURCES_QUERY, variables: { first: 1 } });
    await queryAsUserIsExpectedForbidden(USER_DISINFORMATION_ANALYST, { query: SETTINGS_EDIT_MUTATION, variables: { input: { overlap_top: 15 } } });
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

  it('should refuse a confidence recommendation proposed on a confidence the user no longer has', async () => {
    const { created } = await upsertProposals(testContext, [{
      kind: 'raise_confidence',
      source_id: sourceId,
      fingerprint: `${TEST_FINGERPRINT_PREFIX}-stale-confidence`,
      name: 'Raise the confidence of the test connector',
      rationale: 'Integration test',
      // Proposed when the user had another max confidence than the current one
      payload: { user_id: connectorUserId, current_max_confidence: 1, proposed_max_confidence: 16 },
      evidence: {},
    }], settings, { kinds: [] });
    expect(created.length).toBe(1);
    const recommendationId = created[0].internal_id;
    const before = await queryAsAdminWithSuccess({ query: USER_CONFIDENCE_QUERY, variables: { id: connectorUserId } });

    const refused = await queryAsAdminWithError({ query: APPLY_MUTATION, variables: { id: recommendationId } });
    expect(refused.errors?.[0].message).toContain('changed since this recommendation was proposed');
    const after = await queryAsAdminWithSuccess({ query: USER_CONFIDENCE_QUERY, variables: { id: connectorUserId } });
    expect(after.data.user.user_confidence_level).toEqual(before.data.user.user_confidence_level);
    // Proposed again, so that the next computation refreshes its preview
    const recommendation = await storeLoadById<BasicStoreEntity & { recommendation_status: string }>(testContext, ADMIN_USER, recommendationId, ENTITY_TYPE_SOURCE_RECOMMENDATION);
    expect(recommendation?.recommendation_status).toBe('proposed');
    await deleteElementById(testContext, ADMIN_USER, recommendationId, ENTITY_TYPE_SOURCE_RECOMMENDATION);
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
    // Work queued for the deleted draft goes to the new one
    expect(await resolveDraftForward(firstDraftId)).toEqual({ draftId: renewedDraftId, closed: false });

    const reverted = await queryAsAdminWithSuccess({ query: REVERT_MUTATION, variables: { id: recommendationId } });
    expect(reverted.data.revertSourceRecommendation.status).toBe('reverted');
    const lifted = await storeLoadById<BasicStoreEntitySource>(testContext, ADMIN_USER, target.id, ENTITY_TYPE_SOURCE);
    expect(lifted?.quarantined).toBe(false);
    expect(lifted?.quarantine_draft_id ?? null).toBeNull();
    // The draft kept for review still receives the work queued for the quarantine
    expect(await resolveDraftForward(firstDraftId)).toEqual({ draftId: renewedDraftId, closed: false });
    await deleteDraftWorkspace(testContext, ADMIN_USER, renewedDraftId);
    // Once it is deleted, no draft takes over: the work still queued for either draft is refused
    expect(await resolveDraftForward(firstDraftId)).toEqual({ draftId: renewedDraftId, closed: true });
    expect(await resolveDraftForward(renewedDraftId)).toEqual({ draftId: renewedDraftId, closed: true });
  });

  it('should route the bundles of a quarantined feed into its open quarantine draft', async () => {
    const feedId = uuidv4();
    const feedSource = await createEntity(testContext, ADMIN_USER, {
      source_kind: 'ingestion_feed',
      ref_id: feedId,
      ref_type: 'IngestionRss',
      name: 'Source intelligence test feed',
      source_user_ids: [],
      enabled: true,
      quarantined: false,
    }, ENTITY_TYPE_SOURCE);
    expect(await resolveFeedQuarantineDraftId(testContext, feedId)).toBeUndefined();

    await patchAttribute(testContext, ADMIN_USER, feedSource.internal_id, ENTITY_TYPE_SOURCE, { quarantined: true, quarantine_draft_id: null });
    // The first bundle opens the quarantine draft, the next ones reuse it
    const firstDraftId = await resolveFeedQuarantineDraftId(testContext, feedId) as string;
    expect(firstDraftId).toBeTruthy();
    expect(await resolveFeedQuarantineDraftId(testContext, feedId)).toBe(firstDraftId);

    await deleteDraftWorkspace(testContext, ADMIN_USER, firstDraftId);
    const renewedDraftId = await resolveFeedQuarantineDraftId(testContext, feedId) as string;
    expect(renewedDraftId).toBeTruthy();
    expect(renewedDraftId).not.toBe(firstDraftId);
    // A bundle queued for the deleted draft before its deletion is processed into the new one
    expect(await resolveDraftForward(firstDraftId)).toEqual({ draftId: renewedDraftId, closed: false });

    await patchAttribute(testContext, ADMIN_USER, feedSource.internal_id, ENTITY_TYPE_SOURCE, { quarantined: false, quarantine_draft_id: null });
    expect(await resolveFeedQuarantineDraftId(testContext, feedId)).toBeUndefined();
    await deleteDraftWorkspace(testContext, ADMIN_USER, renewedDraftId);
  });

  it('should refuse the work queued for a first quarantine draft closed after the quarantine was lifted', async () => {
    const createFeedSource = (name: string) => createEntity(testContext, ADMIN_USER, {
      source_kind: 'ingestion_feed',
      ref_id: uuidv4(),
      ref_type: 'IngestionRss',
      name,
      source_user_ids: [],
      enabled: true,
      quarantined: false,
    }, ENTITY_TYPE_SOURCE);

    // Opened by a quarantine recommendation, lifted by its revert before any renewal
    const recommended = await createFeedSource('Source intelligence test feed quarantined by a recommendation');
    const { created } = await upsertProposals(testContext, [{
      kind: 'quarantine',
      source_id: recommended.internal_id,
      fingerprint: `${TEST_FINGERPRINT_PREFIX}-quarantine-first-draft`,
      name: 'Quarantine the test feed into a draft',
      rationale: 'Integration test',
      payload: { target: 'ingestion_feed' },
      evidence: {},
    }], settings, { kinds: [] });
    expect(created.length).toBe(1);
    const applied = await queryAsAdminWithSuccess({ query: APPLY_MUTATION, variables: { id: created[0].internal_id } });
    expect(applied.data.applySourceRecommendation.status).toBe('applied');
    const quarantined = await storeLoadById<BasicStoreEntitySource>(testContext, ADMIN_USER, recommended.internal_id, ENTITY_TYPE_SOURCE);
    const recommendedDraftId = quarantined?.quarantine_draft_id as string;
    expect(recommendedDraftId).toBeTruthy();
    const reverted = await queryAsAdminWithSuccess({ query: REVERT_MUTATION, variables: { id: created[0].internal_id } });
    expect(reverted.data.revertSourceRecommendation.status).toBe('reverted');
    expect(await resolveDraftForward(recommendedDraftId)).toEqual({ draftId: recommendedDraftId, closed: false });
    await deleteDraftWorkspace(testContext, ADMIN_USER, recommendedDraftId);
    expect(await resolveDraftForward(recommendedDraftId)).toEqual({ draftId: recommendedDraftId, closed: true });

    // Opened by the first bundle of a quarantined feed, closed after the quarantine was lifted
    const routed = await createFeedSource('Source intelligence test feed quarantined by routing');
    await patchAttribute(testContext, ADMIN_USER, routed.internal_id, ENTITY_TYPE_SOURCE, { quarantined: true, quarantine_draft_id: null });
    const routedDraftId = await resolveFeedQuarantineDraftId(testContext, routed.ref_id as string) as string;
    expect(routedDraftId).toBeTruthy();
    await patchAttribute(testContext, ADMIN_USER, routed.internal_id, ENTITY_TYPE_SOURCE, { quarantined: false, quarantine_draft_id: null });
    await deleteDraftWorkspace(testContext, ADMIN_USER, routedDraftId);
    expect(await resolveDraftForward(routedDraftId)).toEqual({ draftId: routedDraftId, closed: true });
  });

  it('should keep a failed revert as reverting and complete a retried one', async () => {
    const { created } = await upsertProposals(testContext, [{
      kind: 'change_schedule',
      source_id: sourceId,
      fingerprint: `${TEST_FINGERPRINT_PREFIX}-revert-failure`,
      name: 'Change the schedule of a connector deleted since',
      rationale: 'Integration test',
      payload: { target: 'connector', connector_id: uuidv4(), key: 'CONNECTOR_DURATION_PERIOD', proposed_value: 'PT2H', current_value: 'PT1H' },
      evidence: {},
    }, {
      kind: 'add_deny_list',
      source_id: sourceId,
      fingerprint: `${TEST_FINGERPRINT_PREFIX}-revert-retry`,
      name: 'Remove an exclusion list already removed',
      rationale: 'Integration test',
      payload: {},
      evidence: {},
    }], settings, { kinds: [] });
    expect(created.length).toBe(2);
    const [failing, retried] = created;

    // The connector was deleted after the apply: the revert cannot complete, says why and stays reverting
    await patchAttribute(testContext, ADMIN_USER, failing.internal_id, ENTITY_TYPE_SOURCE_RECOMMENDATION, {
      recommendation_status: 'applied',
      revert_payload: JSON.stringify({ target: 'connector', connector_id: uuidv4(), key: 'CONNECTOR_DURATION_PERIOD', previous_value: 'PT1H' }),
    });
    const failed = await queryAsAdminWithSuccess({ query: REVERT_MUTATION, variables: { id: failing.internal_id } });
    expect(failed.data.revertSourceRecommendation.status).toBe('reverting');
    const kept = await storeLoadById<BasicStoreEntity & { error_message?: string }>(testContext, ADMIN_USER, failing.internal_id, ENTITY_TYPE_SOURCE_RECOMMENDATION);
    expect(kept?.error_message).toContain('Managed connector not found');
    await queryAsAdminWithError({ query: APPLY_MUTATION, variables: { id: failing.internal_id } }, 'Only proposed recommendations can be applied');
    await queryAsAdminWithError({ query: DISMISS_MUTATION, variables: { id: failing.internal_id } }, 'Only proposed recommendations can be dismissed');

    // A revert interrupted after its action ran is retried: the exclusion list it already removed is not needed again
    await patchAttribute(testContext, ADMIN_USER, retried.internal_id, ENTITY_TYPE_SOURCE_RECOMMENDATION, {
      recommendation_status: 'reverting',
      revert_payload: JSON.stringify({ exclusion_list_id: uuidv4() }),
    });
    const completed = await queryAsAdminWithSuccess({ query: REVERT_MUTATION, variables: { id: retried.internal_id } });
    expect(completed.data.revertSourceRecommendation.status).toBe('reverted');
  });

  it('should fail a connector deployment refused before writing and leave a linked connector running on revert', async () => {
    const { created } = await upsertProposals(testContext, [{
      kind: 'add_connector',
      source_id: null,
      fingerprint: `${TEST_FINGERPRINT_PREFIX}-deploy-refused`,
      name: 'Deploy a connector missing from the catalog',
      rationale: 'Integration test',
      payload: { slug: 'missing-connector', title: 'Missing test connector', catalog_id: uuidv4(), contract_image: 'opencti/connector-missing-from-catalog' },
      evidence: {},
    }, {
      kind: 'add_connector',
      source_id: null,
      fingerprint: `${TEST_FINGERPRINT_PREFIX}-deploy-linked`,
      name: 'Link a connector deployed beforehand',
      rationale: 'Integration test',
      payload: { slug: 'linked-connector', title: 'Linked test connector', catalog_id: uuidv4(), contract_image: 'opencti/connector-linked' },
      evidence: {},
    }], settings, { kinds: [] });
    expect(created.length).toBe(2);
    const [refused, linked] = created;

    // The contract is unknown: the deployment refuses before creating anything, so the recommendation fails and can be retried
    const failed = await queryAsAdminWithSuccess({ query: APPLY_MUTATION, variables: { id: refused.internal_id } });
    expect(failed.data.applySourceRecommendation.status).toBe('failed');
    const kept = await storeLoadById<BasicStoreEntity & { error_message?: string }>(testContext, ADMIN_USER, refused.internal_id, ENTITY_TYPE_SOURCE_RECOMMENDATION);
    expect(kept?.error_message).toContain('Target contract not found');
    const retried = await queryAsAdminWithSuccess({ query: APPLY_MUTATION, variables: { id: refused.internal_id } });
    expect(retried.data.applySourceRecommendation.status).toBe('failed');

    // A linked connector was not deployed by the recommendation: the revert does not stop it (this one no longer exists)
    await patchAttribute(testContext, ADMIN_USER, linked.internal_id, ENTITY_TYPE_SOURCE_RECOMMENDATION, {
      recommendation_status: 'applied',
      revert_payload: JSON.stringify({ connector_id: uuidv4(), linked: true }),
    });
    const reverted = await queryAsAdminWithSuccess({ query: REVERT_MUTATION, variables: { id: linked.internal_id } });
    expect(reverted.data.revertSourceRecommendation.status).toBe('reverted');
  });

  it('should create one live recommendation per fingerprint when a deployment and a computation propose it together', async () => {
    const proposal = {
      kind: 'add_connector' as const,
      source_id: null,
      fingerprint: `${TEST_FINGERPRINT_PREFIX}-deploy-concurrent`,
      name: 'Deploy a connector proposed twice at once',
      rationale: 'Integration test',
      payload: { slug: 'concurrent-connector', title: 'Concurrent test connector', catalog_id: uuidv4() },
      evidence: {},
    };
    const [deployed] = await Promise.all([
      findOrCreateProposal(testContext, proposal),
      upsertProposals(testContext, [proposal], settings, { kinds: [] }),
      upsertProposals(testContext, [proposal], settings, { kinds: [] }),
    ]);
    const live = await findRecommendationsByFingerprint(testContext, proposal.fingerprint, ['proposed', 'applying', 'failed', 'applied']);
    expect(live.map((recommendation) => recommendation.internal_id)).toEqual([deployed.internal_id]);
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

  it('should not propose any tuning from a truncated scan', async () => {
    const listRecommendations = () => fullEntitiesList<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_SOURCE_RECOMMENDATION]);
    const existing = await listRecommendations();
    for (let i = 0; i < existing.length; i += 1) {
      await deleteElementById(testContext, ADMIN_USER, existing[i].internal_id, ENTITY_TYPE_SOURCE_RECOMMENDATION);
    }
    // These thresholds propose a decay rule for every source that creates indicators
    const eagerSettings: SourceIntelligenceSettings = {
      ...settings,
      min_author_volume: 1,
      min_manual_volume: 1,
      backfill_days: 0,
      thresholds: { ...settings.thresholds, min_volume: 0, high_noise: 0 },
      autonomy: { ...settings.autonomy, auto_apply_kinds: [] },
    };
    await runFullComputation(testContext, { ...eagerSettings, max_scan_objects: 1 });
    const truncated = await queryAsAdminWithSuccess({ query: STATUS_QUERY });
    expect(truncated.data.sourceIntelligenceStatus.last_scan_truncated).toBe(true);
    // The limit is exact: the object beyond it only tells that the scan is truncated
    expect(truncated.data.sourceIntelligenceStatus.last_scanned_objects).toBe(1);
    expect(await listRecommendations()).toHaveLength(0);
    // The same thresholds over the whole knowledge do propose tuning
    await runFullComputation(testContext, eagerSettings);
    const complete = await queryAsAdminWithSuccess({ query: STATUS_QUERY });
    expect(complete.data.sourceIntelligenceStatus.last_scan_truncated).toBe(false);
    expect((await listRecommendations()).length).toBeGreaterThan(0);
  }, 480000);
});
