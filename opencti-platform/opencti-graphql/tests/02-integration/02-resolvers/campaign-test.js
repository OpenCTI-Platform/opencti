import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { now } from 'moment/moment';
import { ADMIN_USER, testContext, queryAsAdmin } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';

const LIST_QUERY = gql`
  query campaigns(
    $first: Int
    $after: ID
    $orderBy: CampaignsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    campaigns(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          standard_id
          name
          description
        }
      }
    }
  }
`;

const TIMESERIES_QUERY = gql`
  query campaignsTimeSeries(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
    $relationship_type: [String]
  ) {
    campaignsTimeSeries(
      objectId: $objectId
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
      relationship_type: $relationship_type
    ) {
      date
      value
    }
  }
`;

const READ_QUERY = gql`
  query campaign($id: String!) {
    campaign(id: $id) {
      id
      standard_id
      name
      description
      toStix
      created_at
      updated_at
      refreshed_at
    }
  }
`;

describe('Campaign resolver standard behavior', () => {
  let campaignInternalId;
  let campaignCreatedAt;
  let campaignUpdatedAt;
  const campaignStixId = 'campaign--76c42acb-c5d7-4f38-abf2-a8566ac89ac9';
  it('should campaign created', async () => {
    const CREATE_QUERY = gql`
      mutation CampaignAdd($input: CampaignAddInput!) {
        campaignAdd(input: $input) {
          id
          standard_id
          name
          description
          created_at
          updated_at
          refreshed_at
        }
      }
    `;
    // Create the campaign
    const CAMPAIGN_TO_CREATE = {
      input: {
        name: 'Campaign',
        stix_id: campaignStixId,
        description: 'Campaign description',
        first_seen: '2020-03-24T10:51:20+00:00',
        last_seen: '2020-03-24T10:51:20+00:00',
      },
    };
    const campaign = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: CAMPAIGN_TO_CREATE,
    });
    expect(campaign).not.toBeNull();
    expect(campaign.data.campaignAdd).not.toBeNull();
    expect(campaign.data.campaignAdd.name).toEqual('Campaign');
    campaignInternalId = campaign.data.campaignAdd.id;
    campaignCreatedAt = campaign.data.campaignAdd.created_at;
    campaignUpdatedAt = campaign.data.campaignAdd.updated_at;
    expect(campaignCreatedAt).toEqual(campaignUpdatedAt);
    expect(campaignCreatedAt).toEqual(campaign.data.campaignAdd.refreshed_at);
  });
  it('should campaign loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: campaignInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.campaign).not.toBeNull();
    expect(queryResult.data.campaign.id).toEqual(campaignInternalId);
    expect(queryResult.data.campaign.toStix.length).toBeGreaterThan(5);
  });
  it('should campaign loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: campaignStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.campaign).not.toBeNull();
    expect(queryResult.data.campaign.id).toEqual(campaignInternalId);
  });
  it('should list campaigns', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.campaigns.edges.length).toEqual(2);
  });
  it('should timeseries campaigns', async () => {
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        field: 'first_seen',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
      },
    });
    expect(queryResult.data.campaignsTimeSeries.length).toEqual(13);
    expect(queryResult.data.campaignsTimeSeries[2].value).toEqual(1);
  });
  it("should timeseries of an entity's campaigns", async () => {
    const intrusionSet = await elLoadById(testContext, ADMIN_USER, 'intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7');
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        objectId: intrusionSet.internal_id,
        field: 'first_seen',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
        relationship_type: ['attributed-to'],
      },
    });
    expect(queryResult.data.campaignsTimeSeries.length).toEqual(13);
    expect(queryResult.data.campaignsTimeSeries[1].value).toEqual(1);
  });
  it('should update campaign', async () => {
    const UPDATE_QUERY = gql`
      mutation CampaignEdit($id: ID!, $input: [EditInput]!) {
        campaignEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
            created_at
            updated_at
            refreshed_at
          }
        }
      }
    `;
    const editionStartDatetime = now();
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: campaignInternalId, input: { key: 'name', value: ['Campaign - test'] } },
    });
    expect(queryResult.data.campaignEdit.fieldPatch.name).toEqual('Campaign - test');
    expect(queryResult.data.campaignEdit.fieldPatch.created_at).toEqual(campaignCreatedAt);
    // should modify updated_at and refreshed_at
    campaignUpdatedAt = queryResult.data.campaignEdit.fieldPatch.updated_at;
    expect(queryResult.data.campaignEdit.fieldPatch.refreshed_at).toEqual(campaignUpdatedAt);
    expect(campaignCreatedAt < campaignUpdatedAt).toBeTruthy();
    expect(editionStartDatetime < campaignUpdatedAt).toBeTruthy();
  });
  it('should context patch campaign', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation CampaignEdit($id: ID!, $input: EditContext) {
        campaignEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: campaignInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.campaignEdit.contextPatch.id).toEqual(campaignInternalId);
  });
  it('should context clean campaign', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation CampaignEdit($id: ID!) {
        campaignEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: campaignInternalId },
    });
    expect(queryResult.data.campaignEdit.contextClean.id).toEqual(campaignInternalId);
  });
  it('should add relation in campaign', async () => {
    const relationCreationStartDatetime = now();
    const RELATION_ADD_QUERY = gql`
      mutation CampaignEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
        campaignEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on Campaign {
                objectMarking {
                  id
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_ADD_QUERY,
      variables: {
        id: campaignInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.campaignEdit.relationAdd.from.objectMarking.length).toEqual(1);
    // should update updated_at and refreshed_at (because ref relationship creation)
    const campaignQueryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: campaignStixId } });
    expect(campaignQueryResult).not.toBeNull();
    expect(campaignQueryResult.data.campaign.id).toEqual(campaignInternalId);
    expect(campaignQueryResult.data.campaign.created_at).toEqual(campaignCreatedAt);
    expect(relationCreationStartDatetime < campaignQueryResult.data.campaign.updated_at).toBeTruthy();
    expect(relationCreationStartDatetime < campaignQueryResult.data.campaign.refreshed_at).toBeTruthy();
  });
  it('should delete relation in campaign', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation CampaignEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        campaignEdit(id: $id) {
          relationDelete(toId: $toId, relationship_type: $relationship_type) {
            id
            objectMarking {
              id
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: campaignInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.campaignEdit.relationDelete.objectMarking.length).toEqual(0);
  });
  it('should campaign deleted', async () => {
    const DELETE_QUERY = gql`
      mutation campaignDelete($id: ID!) {
        campaignEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the campaign
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: campaignInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: campaignStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.campaign).toBeNull();
  });
});
