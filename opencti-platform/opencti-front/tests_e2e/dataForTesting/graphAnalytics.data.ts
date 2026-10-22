import { APIRequestContext } from '@playwright/test';

const graphqlRequest = async (request: APIRequestContext, query: string, variables: Record<string, unknown>) => {
  const response = await request.post('/graphql', { data: { query, variables } });
  const body = await response.json();
  if (body.errors?.length) {
    throw new Error(`GraphQL error: ${JSON.stringify(body.errors)}`);
  }
  return body.data;
};

export const addIntrusionSet = async (request: APIRequestContext, name: string): Promise<string> => {
  const data = await graphqlRequest(request, `
    mutation GraphAnalyticsE2EIntrusionSetAdd($input: IntrusionSetAddInput!) { intrusionSetAdd(input: $input) { id } }
  `, { input: { name, description: 'graph analytics e2e' } });
  return data.intrusionSetAdd.id;
};

export const addAttackPattern = async (request: APIRequestContext, name: string, mitreId: string): Promise<string> => {
  const data = await graphqlRequest(request, `
    mutation GraphAnalyticsE2EAttackPatternAdd($input: AttackPatternAddInput!) { attackPatternAdd(input: $input) { id } }
  `, { input: { name, x_mitre_id: mitreId, description: 'graph analytics e2e' } });
  return data.attackPatternAdd.id;
};

export const addSector = async (request: APIRequestContext, name: string): Promise<string> => {
  const data = await graphqlRequest(request, `
    mutation GraphAnalyticsE2ESectorAdd($input: SectorAddInput!) { sectorAdd(input: $input) { id } }
  `, { input: { name, description: 'graph analytics e2e' } });
  return data.sectorAdd.id;
};

export const addRelationship = async (request: APIRequestContext, fromId: string, relationshipType: string, toId: string): Promise<string> => {
  const data = await graphqlRequest(request, `
    mutation GraphAnalyticsE2ERelationshipAdd($input: StixCoreRelationshipAddInput!) { stixCoreRelationshipAdd(input: $input) { id } }
  `, { input: { fromId, toId, relationship_type: relationshipType } });
  return data.stixCoreRelationshipAdd.id;
};

export const requestGraphRecompute = async (request: APIRequestContext, ids: string[]) => {
  return graphqlRequest(request, `
    mutation GraphAnalyticsE2ERecompute($ids: [String!]!) { graphAnalyticsRequestRecompute(ids: $ids) }
  `, { ids });
};

const RUN_IN_PROGRESS_RETRIES = 30;

const upsertCompleteAnalyticsRun = async (
  request: APIRequestContext,
  clusterId: string,
  memberIds: string[],
  featureIds: string[],
) => {
  return graphqlRequest(request, `
    mutation GraphAnalyticsE2EUpsert($input: GraphAnalyticsUpsertMetricsInput!) {
      graphAnalyticsUpsertMetrics(input: $input) { run_id updated_entities upserted_clusters }
    }
  `, {
    input: {
      run_id: `e2e-${clusterId}`,
      process_version: 'e2e',
      complete: true,
      metrics: memberIds.map((entity_id) => ({ entity_id, cluster_id: clusterId, cluster_kind: 'campaign', cluster_size: memberIds.length })),
      clusters: [{
        cluster_id: clusterId,
        cluster_kind: 'campaign',
        members_count: memberIds.length,
        representative_ids: memberIds,
        features: [{ family: 'techniques', ids: featureIds }],
      }],
    },
  });
};

/**
 * Write a cluster the way the opencti-analytics process does. Clusters are only published when their run completes,
 * so the run is completed; it waits while a clustering run of the platform holds the single write lease.
 */
export const upsertAnalyticsCluster = async (
  request: APIRequestContext,
  clusterId: string,
  memberIds: string[],
  featureIds: string[],
) => {
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await upsertCompleteAnalyticsRun(request, clusterId, memberIds, featureIds);
    } catch (error) {
      if (attempt >= RUN_IN_PROGRESS_RETRIES || !String(error).includes('Another graph analytics run is in progress')) throw error;
      await new Promise((resolve) => {
        setTimeout(resolve, 2000);
      });
    }
  }
};

export const deleteWorkspace = async (request: APIRequestContext, id: string) => {
  return graphqlRequest(request, `
    mutation GraphAnalyticsE2EWorkspaceDelete($id: ID!) { workspaceDelete(id: $id) }
  `, { id }).catch(() => undefined);
};

export const deleteStixCoreObject = async (request: APIRequestContext, id: string) => {
  return graphqlRequest(request, `
    mutation GraphAnalyticsE2EDelete($id: ID!) { stixCoreObjectEdit(id: $id) { delete } }
  `, { id }).catch(() => undefined);
};
