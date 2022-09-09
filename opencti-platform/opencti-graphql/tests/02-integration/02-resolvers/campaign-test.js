import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';

const LIST_QUERY = gql`
  query campaigns(
    $first: Int
    $after: ID
    $orderBy: CampaignsOrdering
    $orderMode: OrderingMode
    $filters: [CampaignsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    campaigns(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      filterMode: $filterMode
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
    $relationship_type: String
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
    }
  }
`;

describe('Campaign resolver standard behavior', () => {
  let campaignInternalId;
  const campaignStixId = 'campaign--76c42acb-c5d7-4f38-abf2-a8566ac89ac9';
  it('should campaign created', async () => {
    const CREATE_QUERY = gql`
      mutation CampaignAdd($input: CampaignAddInput) {
        campaignAdd(input: $input) {
          id
          standard_id
          name
          description
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
    const intrusionSet = await elLoadById(ADMIN_USER, 'intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7');
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        objectId: intrusionSet.internal_id,
        field: 'first_seen',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
        relationship_type: 'attributed-to',
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
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: campaignInternalId, input: { key: 'name', value: ['Campaign - test'] } },
    });
    expect(queryResult.data.campaignEdit.fieldPatch.name).toEqual('Campaign - test');
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
    const RELATION_ADD_QUERY = gql`
      mutation CampaignEdit($id: ID!, $input: StixMetaRelationshipAddInput!) {
        campaignEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on Campaign {
                objectMarking {
                  edges {
                    node {
                      id
                    }
                  }
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
    expect(queryResult.data.campaignEdit.relationAdd.from.objectMarking.edges.length).toEqual(1);
  });
  it('should delete relation in campaign', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation CampaignEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        campaignEdit(id: $id) {
          relationDelete(toId: $toId, relationship_type: $relationship_type) {
            id
            objectMarking {
              edges {
                node {
                  id
                }
              }
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
    expect(queryResult.data.campaignEdit.relationDelete.objectMarking.edges.length).toEqual(0);
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
