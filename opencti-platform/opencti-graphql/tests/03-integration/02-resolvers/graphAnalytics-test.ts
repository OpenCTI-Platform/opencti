import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext, USER_PARTICIPATE } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { createEntity, createRelation, deleteElementById } from '../../../src/database/middleware';
import { MARKING_TLP_AMBER } from '../../../src/schema/identifier';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_IDENTITY_SECTOR, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE, ENTITY_TYPE_TOOL } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../../../src/modules/grouping/grouping-types';
import { ENTITY_DOMAIN_NAME, ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE } from '../../../src/schema/stixCyberObservable';
import { GRAPH_ANALYTICS_MANAGER_USER } from '../../../src/utils/access';
import { getGraphAnalyticsComputeConfig, processDirtyEntities, runInfrastructureClustering } from '../../../src/modules/graphAnalytics/graphAnalytics-compute';
import { deleteSimilarityRowsForEntities } from '../../../src/modules/graphAnalytics/graphAnalytics-store';
import { redisGraphAnalyticsDeleteState } from '../../../src/database/redis';
import { GRAPH_STATE_ANALYTICS_LAST_RUN_AT } from '../../../src/modules/graphAnalytics/graphAnalytics-state';
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
    }
  }
`;

const PATHS_QUERY = gql`
  query stixPaths($fromId: String!, $toId: String!, $maxDepth: Int, $maxPaths: Int) {
    stixPaths(fromId: $fromId, toId: $toId, maxDepth: $maxDepth, maxPaths: $maxPaths) {
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
    await relate('isA', 'uses', 'malware');
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

  it('should list similar entities with shared evidence', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: SIMILAR_QUERY, variables: { id: ids.isA, first: 10 } });
    const nodes = data.similarEntities.edges.map((e: any) => e.node);
    expect(nodes.map((n: any) => n.entity.id)).toEqual([ids.isB]);
    const [similar] = nodes;
    expect(similar.score).toBeGreaterThan(0.3);
    const evidence = Object.fromEntries(similar.evidence.map((e: any) => [e.family, e.entities.map((x: any) => x.id).sort()]));
    expect(evidence.techniques).toEqual([ids.t1, ids.t2].sort());
    expect(evidence.malware).toEqual([ids.malware]);
    // symmetric row written at the same time
    const reverse = await queryAsAdminWithSuccess({ query: SIMILAR_QUERY, variables: { id: ids.isB } });
    expect(reverse.data.similarEntities.edges.map((e: any) => e.node.entity.id)).toEqual([ids.isA]);
  });

  it('should hide evidence the caller cannot access', async () => {
    const { data } = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: SIMILAR_QUERY, variables: { id: ids.isA } });
    const [similar] = data.similarEntities.edges.map((e: any) => e.node);
    const families = similar.evidence.map((e: any) => e.family);
    expect(families).toContain('techniques');
    expect(families).not.toContain('malware');
    expect(JSON.stringify(similar)).not.toContain(ids.malware);
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
        stixNeighborhoodSummary(id: $id) { id total by_relationship_type { label value } by_entity_type { label value } pairs { relationship_type entity_type value } }
      }
    `;
    const { data } = await queryAsAdminWithSuccess({ query, variables: { id: ids.isA } });
    const summary = data.stixNeighborhoodSummary;
    expect(summary.total).toBe(5);
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
    // filter on the cluster
    const query = gql`
      query members($filters: FilterGroup) { stixCoreObjects(filters: $filters, first: 10) { edges { node { id } } } }
    `;
    const filters = { mode: 'and', filterGroups: [], filters: [{ key: ['graph_cluster_id'], values: [cluster.id] }] };
    const members = await queryAsAdminWithSuccess({ query, variables: { filters } });
    expect(members.data.stixCoreObjects.edges.map((e: any) => e.node.id).sort()).toEqual([ids.d1, ids.d2, ids.d3].sort());
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
        { entity_id: 'unknown-entity-id', betweenness_approx: 0.9 },
      ],
      clusters: [{ cluster_id: clusterId, cluster_kind: 'campaign', members_count: 2, representative_ids: [ids.isA], features: [{ family: 'techniques', ids: [ids.t1, ids.t2] }] }],
    };
    const { data } = await queryAsAdminWithSuccess({ query: upsert, variables: { input } });
    expect(data.graphAnalyticsUpsertMetrics).toEqual(expect.objectContaining({ updated_entities: 2, skipped_entities: 1, upserted_clusters: 1 }));
    expect(data.graphAnalyticsUpsertMetrics.removed_clusters).toBeGreaterThanOrEqual(1);
    // the platform infrastructure cluster is replaced by the analytics run
    const domain = await queryAsAdminWithSuccess({ query: METRICS_QUERY, variables: { id: ids.d1 } });
    expect(domain.data.stixCoreObject.x_opencti_graph_metrics.cluster_id).toBeNull();
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
    const pivot = gql`mutation pivot { graphAnalyticsRecordPivot(kind: similar_open) }`;
    const pivotResult = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: pivot, variables: {} });
    expect(pivotResult.data.graphAnalyticsRecordPivot).toBe(true);
  });

  it('should drop similarity rows of deleted entities', async () => {
    await deleteSimilarityRowsForEntities([ids.isB]);
    const { data } = await queryAsAdminWithSuccess({ query: SIMILAR_QUERY, variables: { id: ids.isA } });
    expect(data.similarEntities.edges).toEqual([]);
  });
});
