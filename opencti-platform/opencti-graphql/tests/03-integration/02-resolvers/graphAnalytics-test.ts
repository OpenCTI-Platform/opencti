import gql from 'graphql-tag';
import { v4 as uuidv4 } from 'uuid';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext, USER_CONNECTOR, USER_PARTICIPATE } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserIsExpectedError, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { createEntity, createRelation, deleteElementById } from '../../../src/database/middleware';
import { MARKING_TLP_AMBER } from '../../../src/schema/identifier';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_IDENTITY_SECTOR, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE, ENTITY_TYPE_TOOL } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../../../src/modules/grouping/grouping-types';
import { ENTITY_DOMAIN_NAME, ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE } from '../../../src/schema/stixCyberObservable';
import { GRAPH_ANALYTICS_MANAGER_USER } from '../../../src/utils/access';
import {
  getGraphAnalyticsComputeConfig,
  isFullPassInProgress,
  processDirtyEntities,
  runFullPassStep,
  runInfrastructureClustering,
  startFullPass,
} from '../../../src/modules/graphAnalytics/graphAnalytics-compute';
import {
  addClusterPromotion,
  deleteSimilarityRowsForEntities,
  listSimilarityRowsBetween,
  loadGraphClusters,
  replaceSimilarityRows,
} from '../../../src/modules/graphAnalytics/graphAnalytics-store';
import { redisGraphAnalyticsDeleteState, redisGraphAnalyticsGetState, redisGraphAnalyticsMarkDirty, redisGraphAnalyticsPopReady } from '../../../src/database/redis';
import {
  GRAPH_STATE_ANALYTICS_LAST_RUN_AT,
  GRAPH_STATE_FULL_PASS_COMPLETED_AT,
  GRAPH_STATE_FULL_PASS_CURSOR,
  GRAPH_STATE_FULL_PASS_ENDED_AT,
  GRAPH_STATE_FULL_PASS_PROCESSED,
  GRAPH_STATE_FULL_PASS_STARTED_AT,
} from '../../../src/modules/graphAnalytics/graphAnalytics-state';
import { ENTITY_TYPE_WORKSPACE } from '../../../src/modules/workspace/workspace-types';
import type { BasicStoreEntity } from '../../../src/types/store';

const SIMILAR_QUERY = gql`
  query similarEntities($id: String!, $first: Int, $minScore: Float) {
    similarEntities(id: $id, first: $first, minScore: $minScore) {
      edges {
        node {
          id
          score
          jaccard
          structural
          shared_count
          entity { id entity_type }
          evidence { family entities { id } }
        }
      }
      pageInfo { globalCount hasNextPage }
    }
  }
`;

const PATHS_QUERY = gql`
  query stixPaths($fromId: String!, $toId: String!, $maxDepth: Int, $maxPaths: Int, $entityTypes: [String!]) {
    stixPaths(fromId: $fromId, toId: $toId, maxDepth: $maxDepth, maxPaths: $maxPaths, entityTypes: $entityTypes) {
      max_depth
      depth_reached
      truncated
      timed_out
      paths {
        length
        node_ids
        relationship_ids
        relationship_types
        nodes { id }
        relationships { id }
      }
    }
  }
`;

const METRICS_QUERY = gql`
  query metrics($id: String!) {
    stixCoreObject(id: $id) {
      id
      x_opencti_graph_metrics {
        degree
        degree_by_type { relationship_type count }
        betweenness_approx
        cluster_id
        cluster_size
        cluster_kind
        computed_at
      }
    }
  }
`;

const CLUSTERS_QUERY = gql`
  query graphClusters($kinds: [GraphClusterKind!]) {
    graphClusters(kinds: $kinds, first: 50) {
      edges {
        node {
          id
          name
          cluster_kind
          cluster_source
          members_count
          representatives { id }
          features { family count entities { id } }
          members(first: 10) { edges { node { id } } }
          timeline(interval: "month") { date value }
        }
      }
    }
  }
`;

describe('Graph analytics resolvers', () => {
  const ids: Record<string, string> = {};
  const created: Array<{ id: string; type: string }> = [];
  const user = GRAPH_ANALYTICS_MANAGER_USER;
  const context = testContext;
  const config = getGraphAnalyticsComputeConfig();

  const create = async (key: string, type: string, input: Record<string, unknown>) => {
    const element = await createEntity(context, ADMIN_USER, input, type) as BasicStoreEntity;
    ids[key] = element.internal_id;
    created.push({ id: element.internal_id, type });
    return element;
  };
  const relate = async (from: string, relationshipType: string, to: string, extra: Record<string, unknown> = {}) => {
    const relation = await createRelation(context, ADMIN_USER, { fromId: ids[from], toId: ids[to], relationship_type: relationshipType, ...extra });
    created.push({ id: relation.internal_id, type: relationshipType });
    return relation;
  };

  beforeAll(async () => {
    await create('isA', ENTITY_TYPE_INTRUSION_SET, { name: 'Graph analytics set A', description: 'test' });
    await create('isB', ENTITY_TYPE_INTRUSION_SET, { name: 'Graph analytics set B', description: 'test' });
    await create('isC', ENTITY_TYPE_INTRUSION_SET, { name: 'Graph analytics set C', description: 'test' });
    await create('t1', ENTITY_TYPE_ATTACK_PATTERN, { name: 'Graph analytics technique 1', x_mitre_id: 'T9901' });
    await create('t2', ENTITY_TYPE_ATTACK_PATTERN, { name: 'Graph analytics technique 2', x_mitre_id: 'T9902' });
    await create('t3', ENTITY_TYPE_ATTACK_PATTERN, { name: 'Graph analytics technique 3', x_mitre_id: 'T9903' });
    await create('tool', ENTITY_TYPE_TOOL, { name: 'Graph analytics tool' });
    // malware restricted to TLP:AMBER, invisible for a TLP:GREEN user
    await create('malware', ENTITY_TYPE_MALWARE, { name: 'Graph analytics malware', is_family: true, objectMarking: [MARKING_TLP_AMBER] });
    await create('sector', ENTITY_TYPE_IDENTITY_SECTOR, { name: 'Graph analytics sector', identity_class: 'class' });
    await relate('isA', 'uses', 't1');
    await relate('isA', 'uses', 't2');
    await relate('isA', 'uses', 'tool');
    // relationship restricted to TLP:AMBER, not counted in the graph metrics of a TLP:GREEN user
    await relate('isA', 'uses', 'malware', { objectMarking: [MARKING_TLP_AMBER] });
    await relate('isA', 'targets', 'sector');
    await relate('isB', 'uses', 't1');
    await relate('isB', 'uses', 't2');
    await relate('isB', 'uses', 'malware');
    await relate('isC', 'uses', 't3');
    // infrastructure sharing one certificate
    await create('cert', ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE, { serial_number: '0f:a1:b2:c3:d4:e5:graph-analytics', issuer: 'CN=Graph analytics test CA' });
    await create('d1', ENTITY_DOMAIN_NAME, { value: 'graph-analytics-1.example.org' });
    await create('d2', ENTITY_DOMAIN_NAME, { value: 'graph-analytics-2.example.org' });
    await create('d3', ENTITY_DOMAIN_NAME, { value: 'graph-analytics-3.example.org' });
    await relate('d1', 'related-to', 'cert');
    await relate('d2', 'related-to', 'cert');
    await relate('d3', 'related-to', 'cert');
    await processDirtyEntities(context, user, Object.values(ids), config);
  });

  afterAll(async () => {
    await deleteSimilarityRowsForEntities(Object.values(ids));
    await redisGraphAnalyticsDeleteState([GRAPH_STATE_ANALYTICS_LAST_RUN_AT]);
    for (let i = created.length - 1; i >= 0; i -= 1) {
      await deleteElementById(context, ADMIN_USER, created[i].id, created[i].type).catch(() => undefined);
    }
  });

  it('should write degree metrics without changing the entity', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: METRICS_QUERY, variables: { id: ids.isA } });
    const metrics = data.stixCoreObject.x_opencti_graph_metrics;
    expect(metrics.degree).toBe(5);
    expect(metrics.degree_by_type).toEqual([{ relationship_type: 'uses', count: 4 }, { relationship_type: 'targets', count: 1 }]);
    expect(metrics.computed_at).toBeDefined();
  });

  it('should filter and sort entities on graph degree', async () => {
    const query = gql`
      query hubs($filters: FilterGroup) {
        stixCoreObjects(types: ["Intrusion-Set"], filters: $filters, orderBy: graph_degree, orderMode: desc, first: 50) {
          edges { node { id } }
        }
      }
    `;
    const filters = { mode: 'and', filterGroups: [], filters: [{ key: ['graph_degree'], values: ['3'], operator: 'gte' }] };
    const { data } = await queryAsAdminWithSuccess({ query, variables: { filters } });
    const resultIds = data.stixCoreObjects.edges.map((e: any) => e.node.id);
    expect(resultIds[0]).toBe(ids.isA);
    expect(resultIds).toContain(ids.isB);
    expect(resultIds).not.toContain(ids.isC);
  });

  it('should count only the relationships a restricted caller can read in graph metrics', async () => {
    const { data } = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: METRICS_QUERY, variables: { id: ids.isA } });
    const metrics = data.stixCoreObject.x_opencti_graph_metrics;
    expect(metrics.degree).toBe(4);
    expect(metrics.degree_by_type).toEqual([{ relationship_type: 'uses', count: 3 }, { relationship_type: 'targets', count: 1 }]);
    expect(metrics.betweenness_approx).toBeNull();
    expect(metrics.computed_at).toBeDefined();
  });

  it('should not count a readable relationship whose other end a restricted caller cannot access', async () => {
    // isB uses the TLP:AMBER malware through an unmarked relationship
    const { data } = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: METRICS_QUERY, variables: { id: ids.isB } });
    const metrics = data.stixCoreObject.x_opencti_graph_metrics;
    expect(metrics.degree).toBe(2);
    expect(metrics.degree_by_type).toEqual([{ relationship_type: 'uses', count: 2 }]);
  });

  it('should reserve graph metrics filtering and sorting to callers reading every relationship', async () => {
    const sorted = gql`
      query restrictedHubs {
        stixCoreObjects(types: ["Intrusion-Set"], orderBy: graph_degree, orderMode: desc, first: 10) { edges { node { id } } }
      }
    `;
    const filtered = gql`
      query restrictedDegree($filters: FilterGroup) {
        stixCoreObjects(types: ["Intrusion-Set"], filters: $filters, first: 10) { edges { node { id } } }
      }
    `;
    const message = 'Graph metrics filtering and sorting require access to every relationship of the platform';
    await queryAsUserIsExpectedError(USER_PARTICIPATE, { query: sorted, variables: {} }, message);
    const filters = { mode: 'and', filterGroups: [], filters: [{ key: ['graph_degree'], values: ['3'], operator: 'gte' }] };
    await queryAsUserIsExpectedError(USER_PARTICIPATE, { query: filtered, variables: { filters } }, message);
  });

  it('should only offer the graph degree filter to callers reading every relationship', async () => {
    const query = gql`
      query graphFilterKeys {
        filterKeysSchema { entity_type filters_schema { filterKey } }
      }
    `;
    const hasGraphDegree = (data: any) => data.filterKeysSchema
      .find((schema: any) => schema.entity_type === 'Intrusion-Set')
      .filters_schema.some((definition: any) => definition.filterKey === 'graph_degree');
    const admin = await queryAsAdminWithSuccess({ query });
    expect(hasGraphDegree(admin.data)).toBe(true);
    const restricted = await queryAsUserWithSuccess(USER_PARTICIPATE, { query });
    expect(hasGraphDegree(restricted.data)).toBe(false);
  });

  it('should list similar entities with shared evidence', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: SIMILAR_QUERY, variables: { id: ids.isA, first: 10 } });
    const nodes = data.similarEntities.edges.map((e: any) => e.node);
    expect(nodes.map((n: any) => n.entity.id)).toEqual([ids.isB]);
    expect(data.similarEntities.pageInfo).toEqual({ globalCount: 1, hasNextPage: false });
    const [similar] = nodes;
    expect(similar.score).toBeGreaterThan(0.3);
    const evidence = Object.fromEntries(similar.evidence.map((e: any) => [e.family, e.entities.map((x: any) => x.id).sort()]));
    expect(evidence.techniques).toEqual([ids.t1, ids.t2].sort());
    expect(evidence.malware).toEqual([ids.malware]);
    // symmetric row written at the same time
    const reverse = await queryAsAdminWithSuccess({ query: SIMILAR_QUERY, variables: { id: ids.isB } });
    expect(reverse.data.similarEntities.edges.map((e: any) => e.node.entity.id)).toEqual([ids.isA]);
  });

  it('should hide evidence the caller cannot access and score without it', async () => {
    const admin = await queryAsAdminWithSuccess({ query: SIMILAR_QUERY, variables: { id: ids.isA } });
    const [adminSimilar] = admin.data.similarEntities.edges.map((e: any) => e.node);
    const { data } = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: SIMILAR_QUERY, variables: { id: ids.isA } });
    const [similar] = data.similarEntities.edges.map((e: any) => e.node);
    const families = similar.evidence.map((e: any) => e.family);
    expect(families).toContain('techniques');
    expect(families).not.toContain('malware');
    expect(JSON.stringify(similar)).not.toContain(ids.malware);
    expect(similar.jaccard).toBeLessThan(adminSimilar.jaccard);
  });

  it('should compute a live similarity matrix', async () => {
    const query = gql`
      query matrix($ids: [String!]!) {
        graphSimilarityMatrix(ids: $ids) { entities { id } cells { source_id target_id score shared_count } }
      }
    `;
    const { data } = await queryAsAdminWithSuccess({ query, variables: { ids: [ids.isA, ids.isB, ids.isC] } });
    const { cells } = data.graphSimilarityMatrix;
    const cell = (a: string, b: string) => cells.find((c: any) => c.source_id === ids[a] && c.target_id === ids[b]);
    expect(cells).toHaveLength(6);
    expect(cell('isA', 'isB').score).toBeGreaterThan(0);
    expect(cell('isA', 'isB').score).toBe(cell('isB', 'isA').score);
    expect(cell('isA', 'isC').score).toBe(0);
  });

  it('should select the most connected entities of a data selection for a similarity matrix', async () => {
    const query = gql`
      query matrixSelection($types: [String!], $filters: FilterGroup, $first: Int) {
        graphSimilarityMatrix(types: $types, filters: $filters, first: $first) { entities { id } cells { source_id target_id score } }
      }
    `;
    const filters = { mode: 'and', filterGroups: [], filters: [{ key: ['name'], values: ['Graph analytics set A', 'Graph analytics set B', 'Graph analytics set C'] }] };
    const { data } = await queryAsAdminWithSuccess({ query, variables: { types: ['Intrusion-Set'], filters, first: 2 } });
    expect(data.graphSimilarityMatrix.entities.map((e: any) => e.id)).toEqual([ids.isA, ids.isB]);
    expect(data.graphSimilarityMatrix.cells).toHaveLength(2);
    const missingSelection = await queryAsAdmin({ query, variables: {} });
    expect(missingSelection.errors?.length).toBe(1);
  });

  it('should find paths between two entities', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: PATHS_QUERY, variables: { fromId: ids.isB, toId: ids.sector, maxDepth: 4, maxPaths: 5 } });
    const { paths } = data.stixPaths;
    expect(paths.length).toBeGreaterThan(0);
    expect(paths[0].length).toBe(3);
    expect(paths[0].node_ids[0]).toBe(ids.isB);
    expect(paths[0].node_ids[3]).toBe(ids.sector);
    expect(paths[0].node_ids).toContain(ids.isA);
    expect(paths[0].nodes.map((n: any) => n.id)).toEqual(paths[0].node_ids);
    expect(paths[0].relationship_types[2]).toBe('targets');
    expect(data.stixPaths.timed_out).toBe(false);
  });

  it('should only restrict the intermediate entities of a path to the requested entity types', async () => {
    // intermediates restricted to attack patterns: the intrusion set endpoints stay eligible
    const variables = { fromId: ids.isB, toId: ids.isA, maxDepth: 2, maxPaths: 5, entityTypes: ['Attack-Pattern'] };
    const { data } = await queryAsAdminWithSuccess({ query: PATHS_QUERY, variables });
    const { paths } = data.stixPaths;
    expect(paths.length).toBe(2);
    paths.forEach((path: any) => {
      expect(path.node_ids[0]).toBe(ids.isB);
      expect(path.node_ids[2]).toBe(ids.isA);
      expect([ids.t1, ids.t2]).toContain(path.node_ids[1]);
    });
  });

  it('should never route a path through an entity the caller cannot access', async () => {
    const { data } = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: PATHS_QUERY, variables: { fromId: ids.isB, toId: ids.sector } });
    data.stixPaths.paths.forEach((path: any) => expect(path.node_ids).not.toContain(ids.malware));
    expect(data.stixPaths.paths.length).toBeGreaterThan(0);
  });

  it('should reject invalid path finder endpoints', async () => {
    const result = await queryAsAdmin({ query: PATHS_QUERY, variables: { fromId: ids.isA, toId: ids.isA } });
    expect(result.errors?.length).toBe(1);
  });

  it('should summarize the neighborhood of an entity', async () => {
    const query = gql`
      query neighborhood($id: String!) {
        stixNeighborhoodSummary(id: $id) { id total by_relationship_type { label value } by_entity_type { label value } pairs { relationship_type entity_type value } truncated }
      }
    `;
    const { data } = await queryAsAdminWithSuccess({ query, variables: { id: ids.isA } });
    const summary = data.stixNeighborhoodSummary;
    expect(summary.total).toBe(5);
    expect(summary.truncated).toBe(false);
    expect(summary.by_relationship_type).toEqual([{ label: 'uses', value: 4 }, { label: 'targets', value: 1 }]);
    expect(summary.by_entity_type).toContainEqual({ label: 'Attack-Pattern', value: 2 });
    expect(summary.pairs).toContainEqual({ relationship_type: 'targets', entity_type: 'Sector', value: 1 });
  });

  it('should cluster infrastructure sharing a certificate and expose it to the caller', async () => {
    const result = await runInfrastructureClustering(context, user, { ...config, clusteringMinSize: 3 });
    expect(result.skipped).toBe(false);
    const { data } = await queryAsAdminWithSuccess({ query: CLUSTERS_QUERY, variables: { kinds: ['infrastructure'] } });
    const cluster = data.graphClusters.edges.map((e: any) => e.node)
      .find((node: any) => node.members.edges.some((m: any) => m.node.id === ids.d1));
    expect(cluster).toBeDefined();
    expect(cluster.cluster_source).toBe('platform');
    expect(cluster.members_count).toBe(3);
    expect(cluster.features).toContainEqual({ family: 'certificates', count: 1, entities: [{ id: ids.cert }] });
    expect(cluster.timeline[cluster.timeline.length - 1].value).toBe(3);
    ids.cluster = cluster.id;
    const metrics = await queryAsAdminWithSuccess({ query: METRICS_QUERY, variables: { id: ids.d2 } });
    expect(metrics.data.stixCoreObject.x_opencti_graph_metrics.cluster_id).toBe(cluster.id);
    expect(metrics.data.stixCoreObject.x_opencti_graph_metrics.cluster_size).toBe(3);
    expect(metrics.data.stixCoreObject.x_opencti_graph_metrics.cluster_kind).toBe('infrastructure');
    // a population above the limit is never clustered partially: the run is skipped and the cluster kept
    const capped = await runInfrastructureClustering(context, user, { ...config, clusteringMinSize: 3, clusteringMaxEntities: 1 });
    expect(capped.skipped).toBe(true);
    const kept = await queryAsAdminWithSuccess({ query: METRICS_QUERY, variables: { id: ids.d2 } });
    expect(kept.data.stixCoreObject.x_opencti_graph_metrics.cluster_id).toBe(cluster.id);
    const limitQuery = gql`query clusterLimit($id: String!) { graphCluster(id: $id) { members_count promotion_max_members } }`;
    const limit = await queryAsAdminWithSuccess({ query: limitQuery, variables: { id: cluster.id } });
    expect(limit.data.graphCluster).toEqual({ members_count: 3, promotion_max_members: 2000 });
    // filter on the cluster
    const query = gql`
      query members($filters: FilterGroup) { stixCoreObjects(filters: $filters, first: 10) { edges { node { id } } } }
    `;
    const filters = { mode: 'and', filterGroups: [], filters: [{ key: ['graph_cluster_id'], values: [cluster.id] }] };
    const members = await queryAsAdminWithSuccess({ query, variables: { filters } });
    expect(members.data.stixCoreObjects.edges.map((e: any) => e.node.id).sort()).toEqual([ids.d1, ids.d2, ids.d3].sort());
    // member filters on the cluster list and on the size series
    const memberQuery = gql`
      query memberClusters($memberFilters: FilterGroup) { graphClusters(memberFilters: $memberFilters, first: 50) { edges { node { id members_count } } } }
    `;
    const domainFilters = { mode: 'and', filterGroups: [], filters: [{ key: ['entity_type'], values: ['Domain-Name'] }] };
    const withDomains = await queryAsAdminWithSuccess({ query: memberQuery, variables: { memberFilters: domainFilters } });
    expect(withDomains.data.graphClusters.edges.map((e: any) => e.node.id)).toContain(cluster.id);
    const setFilters = { mode: 'and', filterGroups: [], filters: [{ key: ['entity_type'], values: ['Intrusion-Set'] }] };
    const withSets = await queryAsAdminWithSuccess({ query: memberQuery, variables: { memberFilters: setFilters } });
    expect(withSets.data.graphClusters.edges.map((e: any) => e.node.id)).not.toContain(cluster.id);
    const sizeQuery = gql`
      query sizes($filters: FilterGroup) {
        graphClustersSizeTimeSeries(interval: "month", filters: $filters, limit: 20) { cluster { id members_count } data { date value } }
      }
    `;
    const sizes = await queryAsAdminWithSuccess({ query: sizeQuery, variables: { filters: domainFilters } });
    const series = sizes.data.graphClustersSizeTimeSeries.find((s: any) => s.cluster.id === cluster.id);
    expect(series.cluster.members_count).toBe(3);
    expect(series.data[series.data.length - 1].value).toBe(3);
  });

  it('should promote a cluster to a grouping and add it to an investigation', async () => {
    const promote = gql`
      mutation promote($id: ID!, $input: GraphClusterPromoteInput!) {
        graphClusterPromote(id: $id, input: $input) { id entity_type ... on Grouping { objects(first: 20) { edges { node { ... on BasicObject { id } } } } } }
      }
    `;
    const { data } = await queryAsAdminWithSuccess({
      query: promote,
      variables: { id: ids.cluster, input: { target: 'Grouping', name: 'Graph analytics promoted cluster', include_features: true } },
    });
    const grouping = data.graphClusterPromote;
    created.push({ id: grouping.id, type: ENTITY_TYPE_CONTAINER_GROUPING });
    expect(grouping.entity_type).toBe('Grouping');
    const objectIds = grouping.objects.edges.map((e: any) => e.node.id);
    expect(objectIds).toEqual(expect.arrayContaining([ids.d1, ids.d2, ids.d3, ids.cert]));
    const clusterQuery = gql`query cluster($id: String!) { graphCluster(id: $id) { id promotedTo { id } } }`;
    const cluster = await queryAsAdminWithSuccess({ query: clusterQuery, variables: { id: ids.cluster } });
    expect(cluster.data.graphCluster.promotedTo.map((p: any) => p.id)).toEqual([grouping.id]);
    const investigate = gql`mutation investigate($id: ID!) { graphClusterAddToInvestigation(id: $id) { id type investigated_entities_ids } }`;
    const investigation = await queryAsAdminWithSuccess({ query: investigate, variables: { id: ids.cluster } });
    created.push({ id: investigation.data.graphClusterAddToInvestigation.id, type: ENTITY_TYPE_WORKSPACE });
    expect(investigation.data.graphClusterAddToInvestigation.type).toBe('investigation');
    expect(investigation.data.graphClusterAddToInvestigation.investigated_entities_ids).toEqual(expect.arrayContaining([ids.d1, ids.d2, ids.d3]));
    // concurrent promotions from the same snapshot all remain linked
    const [snapshot] = await loadGraphClusters(context, ADMIN_USER, [ids.cluster]);
    const concurrentIds = [uuidv4(), uuidv4()];
    await Promise.all(concurrentIds.map((promotedId) => addClusterPromotion(context, snapshot, promotedId)));
    await addClusterPromotion(context, snapshot, grouping.id);
    const [reloaded] = await loadGraphClusters(context, ADMIN_USER, [ids.cluster]);
    expect([...(reloaded.promoted_to_ids ?? [])].sort()).toEqual([grouping.id, ...concurrentIds].sort());
  });

  it('should refuse to complete an analytics run from an account restricted by markings', async () => {
    const upsert = gql`
      mutation upsert($input: GraphAnalyticsUpsertMetricsInput!) {
        graphAnalyticsUpsertMetrics(input: $input) { run_id }
      }
    `;
    const input = { run_id: 'graph-analytics-restricted-run', complete: true, metrics: [] };
    await queryAsUserIsExpectedForbidden(USER_CONNECTOR, { query: upsert, variables: { input } });
  });

  it('should export edges and accept analytics write-back, the latest run owning clusters', async () => {
    const edgesQuery = gql`
      query edges($types: [String!]!) {
        graphAnalyticsEdges(relationshipTypes: $types, first: 5000) { pageInfo { globalCount } edges { node { id relationship_type from_id from_type to_id to_type } } }
      }
    `;
    const edges = await queryAsAdminWithSuccess({ query: edgesQuery, variables: { types: ['uses'] } });
    expect(edges.data.graphAnalyticsEdges.edges.map((e: any) => e.node))
      .toContainEqual(expect.objectContaining({ relationship_type: 'uses', from_id: ids.isA, from_type: 'Intrusion-Set', to_id: ids.t1, to_type: 'Attack-Pattern' }));
    // the relationship to the TLP:AMBER malware is visible to a TLP:GREEN account, its endpoint is not
    const restricted = await queryAsUserWithSuccess(USER_CONNECTOR, { query: edgesQuery, variables: { types: ['uses'] } });
    const restrictedEdges = restricted.data.graphAnalyticsEdges.edges.map((e: any) => e.node);
    expect(restrictedEdges).toContainEqual(expect.objectContaining({ from_id: ids.isA, to_id: ids.t1 }));
    expect(restrictedEdges.some((edge: any) => edge.from_id === ids.malware || edge.to_id === ids.malware)).toBe(false);
    const upsert = gql`
      mutation upsert($input: GraphAnalyticsUpsertMetricsInput!) {
        graphAnalyticsUpsertMetrics(input: $input) { run_id updated_entities skipped_entities upserted_clusters removed_clusters }
      }
    `;
    const clusterId = '155deb88-fd53-5237-b6fa-05f09a5983af';
    const input = {
      run_id: 'graph-analytics-integration-run',
      process_version: 'test',
      complete: true,
      metrics: [
        { entity_id: ids.isA, betweenness_approx: 0.5, cluster_id: clusterId, cluster_size: 2, cluster_kind: 'campaign' },
        { entity_id: ids.isB, betweenness_approx: 0.1, cluster_id: clusterId, cluster_size: 2, cluster_kind: 'campaign' },
        // analyzed by the run but in no cluster: detached from its platform cluster
        { entity_id: ids.d2, betweenness_approx: 0.2, cluster_id: null, cluster_size: null, cluster_kind: null },
        { entity_id: 'unknown-entity-id', betweenness_approx: 0.9 },
      ],
      clusters: [{ cluster_id: clusterId, cluster_kind: 'campaign', members_count: 2, representative_ids: [ids.isA], features: [{ family: 'techniques', ids: [ids.t1, ids.t2] }] }],
    };
    const { data } = await queryAsAdminWithSuccess({ query: upsert, variables: { input } });
    expect(data.graphAnalyticsUpsertMetrics).toEqual(expect.objectContaining({ updated_entities: 3, skipped_entities: 1, upserted_clusters: 1 }));
    expect(data.graphAnalyticsUpsertMetrics.removed_clusters).toBeGreaterThanOrEqual(1);
    // the platform infrastructure cluster is replaced by the analytics run
    const domain = await queryAsAdminWithSuccess({ query: METRICS_QUERY, variables: { id: ids.d1 } });
    expect(domain.data.stixCoreObject.x_opencti_graph_metrics.cluster_id).toBeNull();
    const analyzed = await queryAsAdminWithSuccess({ query: METRICS_QUERY, variables: { id: ids.d2 } });
    expect(analyzed.data.stixCoreObject.x_opencti_graph_metrics.cluster_id).toBeNull();
    expect(analyzed.data.stixCoreObject.x_opencti_graph_metrics.cluster_size).toBeNull();
    expect(analyzed.data.stixCoreObject.x_opencti_graph_metrics.betweenness_approx).toBe(0.2);
    const campaigns = await queryAsAdminWithSuccess({ query: CLUSTERS_QUERY, variables: { kinds: ['campaign'] } });
    const campaignCluster = campaigns.data.graphClusters.edges.map((e: any) => e.node).find((n: any) => n.id === clusterId);
    expect(campaignCluster.cluster_source).toBe('analytics');
    expect(campaignCluster.members_count).toBe(2);
    // while the process is active, the platform leaves clustering to it
    expect((await runInfrastructureClustering(context, user, config)).skipped).toBe(true);
    const statusQuery = gql`query status { graphAnalyticsStatus { analytics_process_active analytics_process_last_run_id analytics_process_version clusters_count similarity_documents } }`;
    const status = await queryAsAdminWithSuccess({ query: statusQuery, variables: {} });
    expect(status.data.graphAnalyticsStatus).toEqual(expect.objectContaining({
      analytics_process_active: true,
      analytics_process_last_run_id: 'graph-analytics-integration-run',
      analytics_process_version: 'test',
    }));
    expect(status.data.graphAnalyticsStatus.similarity_documents).toBeGreaterThanOrEqual(2);
    // the clusters counter counts what the list shows the caller: clusters with at least one accessible member
    const listCountQuery = gql`query clustersCount { graphClusters(first: 1) { pageInfo { globalCount } } }`;
    const adminList = await queryAsAdminWithSuccess({ query: listCountQuery, variables: {} });
    expect(status.data.graphAnalyticsStatus.clusters_count).toBe(adminList.data.graphClusters.pageInfo.globalCount);
    const restrictedStatus = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: statusQuery, variables: {} });
    const restrictedList = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: listCountQuery, variables: {} });
    expect(restrictedStatus.data.graphAnalyticsStatus.clusters_count).toBe(restrictedList.data.graphClusters.pageInfo.globalCount);
    // the similarity counter of a restricted caller leaves out the links to an entity they cannot access
    const linksQuery = gql`query similarityLinks { graphAnalyticsStatus { similarity_documents } }`;
    const adminLinks = async () => (await queryAsAdminWithSuccess({ query: linksQuery, variables: {} })).data.graphAnalyticsStatus.similarity_documents;
    const restrictedLinks = async () => (await queryAsUserWithSuccess(USER_PARTICIPATE, { query: linksQuery, variables: {} })).data.graphAnalyticsStatus.similarity_documents;
    const [adminBefore, restrictedBefore] = [await adminLinks(), await restrictedLinks()];
    expect(restrictedBefore).toBeGreaterThanOrEqual(2);
    await replaceSimilarityRows(context, ADMIN_USER, { id: ids.malware, entity_type: ENTITY_TYPE_MALWARE }, [
      { target_id: ids.isA, target_type: ENTITY_TYPE_INTRUSION_SET, score: 0.9, jaccard: 0.9, structural: 0.9, shared: {}, shared_count: 1 },
    ], 20);
    try {
      expect(await adminLinks()).toBe(adminBefore + 2);
      expect(await restrictedLinks()).toBe(restrictedBefore);
    } finally {
      await deleteSimilarityRowsForEntities([ids.malware]);
    }
  });

  it('should apply an analytics run only when it completes', async () => {
    const upsert = gql`
      mutation upsertStaged($input: GraphAnalyticsUpsertMetricsInput!) { graphAnalyticsUpsertMetrics(input: $input) { run_id } }
    `;
    const runId = `graph-analytics-staged-run-${uuidv4()}`;
    const clusterId = uuidv4();
    const before = (await queryAsAdminWithSuccess({ query: METRICS_QUERY, variables: { id: ids.isC } })).data.stixCoreObject.x_opencti_graph_metrics;
    const partial = {
      run_id: runId,
      process_version: 'test',
      complete: false,
      metrics: [{ entity_id: ids.isC, betweenness_approx: 0.7, cluster_id: clusterId, cluster_size: 1, cluster_kind: 'campaign' }],
      clusters: [{ cluster_id: clusterId, cluster_kind: 'campaign', members_count: 1, representative_ids: [ids.isC], features: [] }],
    };
    await queryAsAdminWithSuccess({ query: upsert, variables: { input: partial } });
    // an interrupted run never shows: the live metrics are the ones of the last completed run
    const staged = (await queryAsAdminWithSuccess({ query: METRICS_QUERY, variables: { id: ids.isC } })).data.stixCoreObject.x_opencti_graph_metrics;
    expect(staged.cluster_id).toBe(before?.cluster_id ?? null);
    expect(staged.betweenness_approx).toBe(before?.betweenness_approx ?? null);
    const stagedClusters = await queryAsAdminWithSuccess({ query: CLUSTERS_QUERY, variables: { kinds: ['campaign'] } });
    expect(stagedClusters.data.graphClusters.edges.map((e: any) => e.node.id)).not.toContain(clusterId);
    // a second run cannot overwrite the staged values of the run in progress
    const concurrent = { ...partial, run_id: `graph-analytics-concurrent-run-${uuidv4()}` };
    const rejected = await queryAsAdmin({ query: upsert, variables: { input: concurrent } });
    expect(rejected.errors?.[0]?.message).toBe('Another graph analytics run is in progress');
    const completion = { run_id: runId, process_version: 'test', complete: true, metrics: [], clusters: [] };
    await queryAsAdminWithSuccess({ query: upsert, variables: { input: completion } });
    const applied = (await queryAsAdminWithSuccess({ query: METRICS_QUERY, variables: { id: ids.isC } })).data.stixCoreObject.x_opencti_graph_metrics;
    expect(applied.cluster_id).toBe(clusterId);
    expect(applied.cluster_size).toBe(1);
    expect(applied.betweenness_approx).toBe(0.7);
    const { data } = await queryAsAdminWithSuccess({ query: CLUSTERS_QUERY, variables: { kinds: ['campaign'] } });
    const cluster = data.graphClusters.edges.map((e: any) => e.node).find((n: any) => n.id === clusterId);
    expect(cluster.timeline[cluster.timeline.length - 1].value).toBe(1);
  });

  it('should keep the identity of a cluster when a run computes another id for the same community', async () => {
    const upsert = gql`
      mutation upsertLineage($input: GraphAnalyticsUpsertMetricsInput!) { graphAnalyticsUpsertMetrics(input: $input) { run_id } }
    `;
    const run = (runId: string, clusterId: string, members: string[]) => ({
      run_id: runId,
      process_version: 'test',
      complete: true,
      metrics: members.map((id) => ({ entity_id: ids[id], betweenness_approx: 0.1, cluster_id: clusterId, cluster_size: members.length, cluster_kind: 'campaign' })),
      clusters: [{ cluster_id: clusterId, cluster_kind: 'campaign', members_count: members.length, representative_ids: [ids[members[0]]], features: [] }],
    });
    // isC is left alone in the cluster of the previous test: a first run including it would continue that cluster
    const original = uuidv4();
    await queryAsAdminWithSuccess({ query: upsert, variables: { input: run(`graph-analytics-lineage-1-${uuidv4()}`, original, ['isA', 'isB', 'tool']) } });
    const first = (await queryAsAdminWithSuccess({ query: METRICS_QUERY, variables: { id: ids.tool } })).data.stixCoreObject.x_opencti_graph_metrics;
    expect(first.cluster_id).toBe(original);
    // the community grew and its provisional id changed: it continues the original cluster
    const provisional = uuidv4();
    await queryAsAdminWithSuccess({ query: upsert, variables: { input: run(`graph-analytics-lineage-2-${uuidv4()}`, provisional, ['isA', 'isB', 'tool', 'isC']) } });
    const grown = (await queryAsAdminWithSuccess({ query: METRICS_QUERY, variables: { id: ids.isC } })).data.stixCoreObject.x_opencti_graph_metrics;
    expect(grown.cluster_id).toBe(original);
    const { data } = await queryAsAdminWithSuccess({ query: CLUSTERS_QUERY, variables: { kinds: ['campaign'] } });
    const listed = data.graphClusters.edges.map((e: any) => e.node);
    expect(listed.map((node: any) => node.id)).not.toContain(provisional);
    expect(listed.find((node: any) => node.id === original)?.members_count).toBe(4);
  });

  it('should give a split cluster its id when the fragment holding the old anchor is the minority', async () => {
    const upsert = gql`
      mutation upsertSplit($input: GraphAnalyticsUpsertMetricsInput!) { graphAnalyticsUpsertMetrics(input: $input) { run_id } }
    `;
    // the previous test left isA, isB, isC and tool in one cluster
    const previousId = (await queryAsAdminWithSuccess({ query: METRICS_QUERY, variables: { id: ids.isA } })).data.stixCoreObject.x_opencti_graph_metrics.cluster_id;
    expect(previousId).toBeTruthy();
    const majority = uuidv4();
    const metric = (key: string, clusterId: string, size: number) => ({ entity_id: ids[key], betweenness_approx: 0.1, cluster_id: clusterId, cluster_size: size, cluster_kind: 'campaign' });
    const input = {
      run_id: `graph-analytics-split-${uuidv4()}`,
      process_version: 'test',
      complete: true,
      metrics: [metric('isB', majority, 3), metric('isC', majority, 3), metric('tool', majority, 3), metric('isA', previousId, 1)],
      clusters: [
        { cluster_id: majority, cluster_kind: 'campaign', members_count: 3, representative_ids: [ids.isB], features: [] },
        // the fragment holding the old anchor computes the previous id
        { cluster_id: previousId, cluster_kind: 'campaign', members_count: 1, representative_ids: [ids.isA], features: [] },
      ],
    };
    await queryAsAdminWithSuccess({ query: upsert, variables: { input } });
    const kept = (await queryAsAdminWithSuccess({ query: METRICS_QUERY, variables: { id: ids.tool } })).data.stixCoreObject.x_opencti_graph_metrics;
    expect(kept.cluster_id).toBe(previousId);
    const moved = (await queryAsAdminWithSuccess({ query: METRICS_QUERY, variables: { id: ids.isA } })).data.stixCoreObject.x_opencti_graph_metrics;
    expect(moved.cluster_id).toBeTruthy();
    expect([previousId, majority]).not.toContain(moved.cluster_id);
    const { data } = await queryAsAdminWithSuccess({ query: CLUSTERS_QUERY, variables: { kinds: ['campaign'] } });
    const listed = data.graphClusters.edges.map((e: any) => e.node);
    expect(listed.map((node: any) => node.id)).not.toContain(majority);
    expect(listed.find((node: any) => node.id === previousId)?.members_count).toBe(3);
    expect(listed.find((node: any) => node.id === moved.cluster_id)?.members_count).toBe(1);
  });

  it('should reject analytics write-back with invalid cluster identifiers', async () => {
    const upsert = gql`
      mutation upsert($input: GraphAnalyticsUpsertMetricsInput!) { graphAnalyticsUpsertMetrics(input: $input) { run_id } }
    `;
    const result = await queryAsAdmin({
      query: upsert,
      variables: { input: { run_id: 'invalid', metrics: [{ entity_id: ids.isA, cluster_id: 'not-a-uuid', cluster_kind: 'campaign', cluster_size: 1 }] } },
    });
    expect(result.errors?.length).toBe(1);
  });

  it('should queue recompute requests and record pivots', async () => {
    const mutation = gql`mutation recompute($ids: [String!]!) { graphAnalyticsRequestRecompute(ids: $ids) }`;
    const { data } = await queryAsAdminWithSuccess({ query: mutation, variables: { ids: [ids.isA, 'unknown-entity-id'] } });
    expect(data.graphAnalyticsRequestRecompute).toBe(1);
    // explicit requests are served at the next tick, whatever the debounce of the backlog
    const ready = await redisGraphAnalyticsPopReady(0, 10);
    expect(ready).toContain(ids.isA);
    const pendingQuery = gql`query pending { graphAnalyticsPendingEntities(first: 10) { id } }`;
    await queryAsAdminWithSuccess({ query: mutation, variables: { ids: [ids.isA] } });
    const { data: pendingData } = await queryAsAdminWithSuccess({ query: pendingQuery, variables: {} });
    expect(pendingData.graphAnalyticsPendingEntities.map((entity: { id: string }) => entity.id)).toContain(ids.isA);
    // listing the queue does not consume it
    expect(await redisGraphAnalyticsPopReady(0, 10)).toContain(ids.isA);
    // an explicit request moves a debounced entity to the priority queue instead of queuing it twice
    await redisGraphAnalyticsMarkDirty([ids.isA]);
    await queryAsAdminWithSuccess({ query: mutation, variables: { ids: [ids.isA] } });
    expect(await redisGraphAnalyticsPopReady(0, 10)).toContain(ids.isA);
    expect(await redisGraphAnalyticsPopReady(Date.now() + 3600 * 1000, 100)).not.toContain(ids.isA);
    // queued entities a restricted user cannot access are skipped, the next accessible ones are listed
    const queuedAt = Date.now() - 1000;
    await redisGraphAnalyticsMarkDirty([ids.malware], queuedAt);
    await redisGraphAnalyticsMarkDirty([ids.isB], queuedAt + 1);
    const restrictedPending = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: gql`query pendingOne { graphAnalyticsPendingEntities(first: 1) { id } }`, variables: {} });
    expect(restrictedPending.data.graphAnalyticsPendingEntities.map((entity: { id: string }) => entity.id)).toEqual([ids.isB]);
    // the waiting count leaves out the queued entities the caller cannot access, like the list it opens
    const pendingCountQuery = gql`query pendingCount { graphAnalyticsStatus { pending_entities } }`;
    const adminCount = (await queryAsAdminWithSuccess({ query: pendingCountQuery, variables: {} })).data.graphAnalyticsStatus.pending_entities;
    const restrictedCount = (await queryAsUserWithSuccess(USER_PARTICIPATE, { query: pendingCountQuery, variables: {} })).data.graphAnalyticsStatus.pending_entities;
    expect(adminCount).toBeGreaterThanOrEqual(2);
    expect(restrictedCount).toBeGreaterThanOrEqual(1);
    expect(restrictedCount).toBeLessThan(adminCount);
    const restrictedList = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: gql`query pendingAll { graphAnalyticsPendingEntities(first: 100) { id } }`, variables: {} });
    expect(restrictedList.data.graphAnalyticsPendingEntities.length).toBe(Math.min(restrictedCount, 100));
    await redisGraphAnalyticsPopReady(Date.now() + 3600 * 1000, 100);
    const pivot = gql`mutation pivot { graphAnalyticsRecordPivot(kind: similar_open) }`;
    const pivotResult = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: pivot, variables: {} });
    expect(pivotResult.data.graphAnalyticsRecordPivot).toBe(true);
  });

  it('should resume a capped full pass where the previous one stopped', async () => {
    const capped = { ...config, fullPassBatchSize: 2, fullPassMaxEntities: 2 };
    try {
      const completedBefore = (await redisGraphAnalyticsGetState())[GRAPH_STATE_FULL_PASS_COMPLETED_AT];
      await startFullPass();
      const first = await runFullPassStep(context, user, capped, 60000);
      expect(first).toEqual({ processed: 2, outcome: 'capped' });
      const firstState = await redisGraphAnalyticsGetState();
      const firstCursor = firstState[GRAPH_STATE_FULL_PASS_CURSOR];
      expect(firstCursor).toBeTruthy();
      // the pass ended, but it did not refresh every entity: it is not reported as a completed full pass
      expect(firstState[GRAPH_STATE_FULL_PASS_ENDED_AT]).toBeTruthy();
      expect(firstState[GRAPH_STATE_FULL_PASS_COMPLETED_AT]).toEqual(completedBefore);
      expect(isFullPassInProgress(firstState)).toBe(false);
      await startFullPass();
      const second = await runFullPassStep(context, user, capped, 60000);
      expect(second).toEqual({ processed: 2, outcome: 'capped' });
      const secondCursor = (await redisGraphAnalyticsGetState())[GRAPH_STATE_FULL_PASS_CURSOR];
      expect(secondCursor).toBeTruthy();
      expect(secondCursor).not.toEqual(firstCursor);
      // a cap that is not a multiple of the batch size is never exceeded: the last page stops at the cap
      await startFullPass();
      const third = await runFullPassStep(context, user, { ...config, fullPassBatchSize: 2, fullPassMaxEntities: 3 }, 60000);
      expect(third).toEqual({ processed: 3, outcome: 'capped' });
      const thirdState = await redisGraphAnalyticsGetState();
      expect(thirdState[GRAPH_STATE_FULL_PASS_PROCESSED]).toEqual('3');
      expect(thirdState[GRAPH_STATE_FULL_PASS_CURSOR]).not.toEqual(secondCursor);
    } finally {
      await redisGraphAnalyticsDeleteState([
        GRAPH_STATE_FULL_PASS_CURSOR,
        GRAPH_STATE_FULL_PASS_STARTED_AT,
        GRAPH_STATE_FULL_PASS_COMPLETED_AT,
        GRAPH_STATE_FULL_PASS_ENDED_AT,
        GRAPH_STATE_FULL_PASS_PROCESSED,
      ]);
      await redisGraphAnalyticsPopReady(Date.now(), 100);
    }
  });

  it('should only drop the incoming similarity rows of entities that are no longer candidates', async () => {
    const [source, kept, refreshed, stale] = [uuidv4(), uuidv4(), uuidv4(), uuidv4()].map((id) => ({ id, entity_type: ENTITY_TYPE_INTRUSION_SET }));
    const scoreOf = (target: { id: string; entity_type: string }, score: number) => ({
      target_id: target.id, target_type: target.entity_type, score, jaccard: score, structural: score, shared: {}, shared_count: 1,
    });
    const allIds = [source.id, kept.id, refreshed.id, stale.id];
    try {
      // refreshed and stale both keep the source in their own top-N
      await replaceSimilarityRows(context, ADMIN_USER, refreshed, [scoreOf(source, 0.2)], 1);
      await replaceSimilarityRows(context, ADMIN_USER, stale, [scoreOf(source, 0.2)], 1);
      await replaceSimilarityRows(context, ADMIN_USER, source, [scoreOf(kept, 0.9), scoreOf(refreshed, 0.5)], 1);
      const rows = await listSimilarityRowsBetween(context, ADMIN_USER, allIds);
      const described = rows.map((row) => `${row.similarity_entity_id}>${row.similarity_target_id}:${row.similarity_score}`).sort();
      expect(described).toEqual([
        `${source.id}>${kept.id}:0.9`,
        `${kept.id}>${source.id}:0.9`,
        `${refreshed.id}>${source.id}:0.5`,
      ].sort());
    } finally {
      await deleteSimilarityRowsForEntities(allIds);
    }
  });

  it('should keep at most the top-N similarity rows of an entity when writing the reverse rows', async () => {
    const [hub, weak, strong, middle, faint] = [uuidv4(), uuidv4(), uuidv4(), uuidv4(), uuidv4()].map((id) => ({ id, entity_type: ENTITY_TYPE_INTRUSION_SET }));
    const scoreOf = (target: { id: string; entity_type: string }, score: number) => ({
      target_id: target.id, target_type: target.entity_type, score, jaccard: score, structural: score, shared: {}, shared_count: 1,
    });
    const allIds = [hub.id, weak.id, strong.id, middle.id, faint.id];
    const hubRows = async () => (await listSimilarityRowsBetween(context, ADMIN_USER, allIds))
      .filter((row) => row.similarity_entity_id === hub.id)
      .map((row) => `${row.similarity_target_id}:${row.similarity_score}`)
      .sort();
    try {
      // with a top-2, the hub keeps the two best of the entities listing it, the weakest is pushed out
      await replaceSimilarityRows(context, ADMIN_USER, weak, [scoreOf(hub, 0.3)], 2);
      await replaceSimilarityRows(context, ADMIN_USER, strong, [scoreOf(hub, 0.5)], 2);
      await replaceSimilarityRows(context, ADMIN_USER, middle, [scoreOf(hub, 0.4)], 2);
      expect(await hubRows()).toEqual([`${strong.id}:0.5`, `${middle.id}:0.4`].sort());
      // a lower score does not enter the top-N of the hub
      await replaceSimilarityRows(context, ADMIN_USER, faint, [scoreOf(hub, 0.1)], 2);
      expect(await hubRows()).toEqual([`${strong.id}:0.5`, `${middle.id}:0.4`].sort());
      // every entity still lists the hub in its own top-N
      const incoming = (await listSimilarityRowsBetween(context, ADMIN_USER, allIds)).filter((row) => row.similarity_target_id === hub.id);
      expect(incoming.map((row) => row.similarity_entity_id).sort()).toEqual([weak.id, strong.id, middle.id, faint.id].sort());
      // a row already in the top-N of the hub is refreshed in place
      await replaceSimilarityRows(context, ADMIN_USER, strong, [scoreOf(hub, 0.2)], 2);
      expect(await hubRows()).toEqual([`${strong.id}:0.2`, `${middle.id}:0.4`].sort());
    } finally {
      await deleteSimilarityRowsForEntities(allIds);
    }
  });

  it('should drop similarity rows of deleted entities', async () => {
    await deleteSimilarityRowsForEntities([ids.isB]);
    const { data } = await queryAsAdminWithSuccess({ query: SIMILAR_QUERY, variables: { id: ids.isA } });
    expect(data.similarEntities.edges).toEqual([]);
  });
});
