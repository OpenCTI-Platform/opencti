import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { ANALYST_USER, participantQuery, queryAsAdmin, serverFromUser } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query cases(
    $first: Int
    $after: ID
    $orderBy: CasesOrdering
    $orderMode: OrderingMode
    $filters: [CasesFiltering!]
    $filterMode: FilterMode
    $search: String
  ) {
    cases(
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

const READ_QUERY = gql`
  query case($id: String!) {
    case(id: $id) {
      id
      standard_id
      name
      description
      toStix
    }
  }
`;

const analystApolloServer = serverFromUser(ANALYST_USER);
export const queryAsAnalyst = (request) => analystApolloServer.executeOperation(request);
const queryAsDefault = (request) => participantQuery(request);

describe('Case resolver standard behavior', () => {
  let caseInternalId;
  const caseStixId = 'feedback--f505027c-997d-4243-b67c-471f994e20d5';
  it('should case created', async () => {
    const CREATE_QUERY = gql`
      mutation FeedbackAdd($input: FeedbackAddInput!) {
        feedbackAdd(input: $input) {
          id
          standard_id
          name
          description
        }
      }
    `;
    // Create the case
    const DATA_COMPONENT_TO_CREATE = {
      input: {
        name: 'Feedback',
        stix_id: caseStixId,
        description: 'Feedback description',
      },
    };
    const caseData = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: DATA_COMPONENT_TO_CREATE,
    });
    expect(caseData).not.toBeNull();
    expect(caseData.data.feedbackAdd).not.toBeNull();
    expect(caseData.data.feedbackAdd.name).toEqual('Feedback');
    caseInternalId = caseData.data.feedbackAdd.id;
  });
  it('should case loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: caseInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.case).not.toBeNull();
    expect(queryResult.data.case.id).toEqual(caseInternalId);
    expect(queryResult.data.case.toStix.length).toBeGreaterThan(5);
  });
  it('should case loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: caseStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.case).not.toBeNull();
    expect(queryResult.data.case.id).toEqual(caseInternalId);
  });
  it('should list cases', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.cases.edges.length).toEqual(1);
  });
  it('should update case', async () => {
    const UPDATE_QUERY = gql`
      mutation CaseEdit($id: ID!, $input: [EditInput]!) {
        stixDomainObjectEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            ... on Case {
              name
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: caseInternalId, input: { key: 'name', value: ['Case - test'] } },
    });
    expect(queryResult.data.stixDomainObjectEdit.fieldPatch.name).toEqual('Case - test');
  });
  it('should context patch case', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation CaseEdit($id: ID!, $input: EditContext!) {
        stixDomainObjectEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: caseInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.stixDomainObjectEdit.contextPatch.id).toEqual(caseInternalId);
  });
  it('should context clean case', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation CaseEdit($id: ID!, $input: EditContext!) {
        stixDomainObjectEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: caseInternalId, input: { focusOn: '' } },
    });
    expect(queryResult.data.stixDomainObjectEdit.contextPatch.id).toEqual(caseInternalId);
  });
  it('should case deleted', async () => {
    const DELETE_QUERY = gql`
      mutation caseDelete($id: ID!) {
        caseDelete(id: $id)
      }
    `;
    // Delete the case
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: caseInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: caseStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.case).toBeNull();
  });
});

describe('Incident response resolver RBAC behavior', () => {
  let incidentResponseInternalId;
  const incidentResponseStixId = 'case-incident--1836367a-8394-5992-9851-01062d890e33';
  const INCIDENT_RESPONSE_NAME = 'Test Incident Response';

  const READ_ALL_QUERY = gql`
    query {
      caseIncidents {
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

  const READ_BY_ID = gql`
    query ($id: String!) {
      caseIncident(id: $id) {
        id
        standard_id
        name
        description
      }
    }
  `;

  const CREATE_QUERY = gql`
    mutation IncidentResponseAdd($input: CaseIncidentAddInput!) {
      caseIncidentAdd(input: $input) {
        id
        standard_id
        name
        description
      }
    }
  `;

  it('should create as analyst', async () => {
    const INCIDENT_RESPONSE_DATA = {
      input: {
        name: INCIDENT_RESPONSE_NAME,
        stix_id: incidentResponseStixId,
        description: 'A test incident response',
      },
    };
    const data = await queryAsAnalyst({
      query: CREATE_QUERY,
      variables: INCIDENT_RESPONSE_DATA,
    });
    expect(data?.data?.caseIncidentAdd).not.toBeNull();
    expect(data.data.caseIncidentAdd.name).toEqual(INCIDENT_RESPONSE_NAME);
    incidentResponseInternalId = data.data.caseIncidentAdd.id;
  });
  it('should retrieve all as analyst', async () => {
    const queryResult = await queryAsAnalyst({
      query: READ_ALL_QUERY,
    });
    expect(queryResult?.data?.caseIncidents).not.toBeNull();
    expect(queryResult.data.caseIncidents.edges).not.toBeNull();
    expect(queryResult.data.caseIncidents.edges.length).toBeGreaterThan(0);
  });
  it('should retrieve by internal id as analyst', async () => {
    const queryResult = await queryAsAnalyst({
      query: READ_BY_ID,
      variables: {
        id: incidentResponseInternalId,
      },
    });
    expect(queryResult?.data?.caseIncident).not.toBeNull();
    expect(queryResult.data.caseIncident.name).toEqual(INCIDENT_RESPONSE_NAME);
  });
  it('should retrieve by stix id as analyst', async () => {
    const queryResult = await queryAsAnalyst({
      query: READ_BY_ID,
      variables: {
        id: incidentResponseStixId,
      },
    });
    expect(queryResult?.data?.caseIncident).not.toBeNull();
    expect(queryResult.data.caseIncident.name).toEqual(INCIDENT_RESPONSE_NAME);
  });
  it('should update as analyst', async () => {
    const UPDATED_DESCRIPTION = 'this is an updated description';
    const UPDATE_QUERY = gql`
      mutation IncidentResponseEdit($id: ID!, $input: [EditInput]!) {
        caseIncidentEdit(id:$id, input:$input) {
          description
        }
      }
    `;
    const queryResult = await queryAsAnalyst({
      query: UPDATE_QUERY,
      variables: {
        id: incidentResponseInternalId,
        input: [{ key: 'description', value: UPDATED_DESCRIPTION }],
      },
    });
    expect(queryResult?.data?.caseIncidentEdit?.description)
      .toEqual(UPDATED_DESCRIPTION);
  });
  it('should not create without rbac', async () => {
    const IR_ID = 'case-incident--01bd6fff-130a-4a49-88f9-f83f0bec84b5';
    const INCIDENT_RESPONSE_DATA = {
      input: {
        name: 'this should not work',
        stix_id: IR_ID,
      }
    };
    let data = await queryAsDefault({
      query: CREATE_QUERY,
      variables: INCIDENT_RESPONSE_DATA,
    });
    expect(data?.errors?.[0].message).toEqual("You are not allowed to do this.");
    expect(data.errors[0].name).toEqual("ForbiddenAccess");
    expect(data.errors[0].data?.http_status).toEqual(403);
    expect(data?.data?.caseIncidentAdd).toBeNull();
    data = await queryAsDefault({
      query: READ_BY_ID,
      variables: { id: IR_ID },
    });
    expect(data?.data?.caseIncident).toBeNull();
  });
  it('should delete as analyst', async () => {
    const DELETE_QUERY = gql`
      mutation IncidentResponseDelete($id: ID!) {
        caseIncidentDelete(id: $id)
      }
    `;
    await queryAsAnalyst({
      query: DELETE_QUERY,
      variables: { id: incidentResponseInternalId },
    });
    // Verify incident response is no longer found
    const queryResult = await queryAsAnalyst({
      query: READ_BY_ID,
      variables: { id: incidentResponseStixId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.caseIncident).toBeNull();
  });
});

describe('RFI resolver RBAC behavior', () => {
  let rfiInternalId;
  const rfiStixId = 'case-rfi--41de54d0-f069-5686-a497-1b292096cb83';
  const RFI_NAME = 'Test RFI';

  const READ_ALL_QUERY = gql`
    query {
      caseRfis {
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

  const READ_BY_ID = gql`
    query ($id: String!) {
      caseRfi(id: $id) {
        id
        standard_id
        name
        description
      }
    }
  `;

  const CREATE_QUERY = gql`
    mutation RFIAdd($input: CaseRfiAddInput!) {
      caseRfiAdd(input: $input) {
        id
        standard_id
        name
        description
      }
    }
  `;

  it('should create as analyst', async () => {
    const RFI_DATA = {
      input: {
        name: RFI_NAME,
        stix_id: rfiStixId,
        description: 'A test rfi',
      },
    };
    const data = await queryAsAnalyst({
      query: CREATE_QUERY,
      variables: RFI_DATA,
    });
    expect(data?.data?.caseRfiAdd).not.toBeNull();
    expect(data.data.caseRfiAdd.name).toEqual(RFI_NAME);
    rfiInternalId = data.data.caseRfiAdd.id;
  });
  it('should retrieve all as analyst', async () => {
    const queryResult = await queryAsAnalyst({
      query: READ_ALL_QUERY,
    });
    expect(queryResult?.data?.caseRfis).not.toBeNull();
    expect(queryResult.data.caseRfis.edges).not.toBeNull();
    expect(queryResult.data.caseRfis.edges.length).toBeGreaterThan(0);
  });
  it('should retrieve by internal id as analyst', async () => {
    const queryResult = await queryAsAnalyst({
      query: READ_BY_ID,
      variables: {
        id: rfiInternalId,
      },
    });
    expect(queryResult?.data?.caseRfi).not.toBeNull();
    expect(queryResult.data.caseRfi.name).toEqual(RFI_NAME);
  });
  it('should retrieve by stix id as analyst', async () => {
    const queryResult = await queryAsAnalyst({
      query: READ_BY_ID,
      variables: {
        id: rfiStixId,
      },
    });
    expect(queryResult?.data?.caseRfi).not.toBeNull();
    expect(queryResult.data.caseRfi.name).toEqual(RFI_NAME);
  });
  it('should update as analyst', async () => {
    const UPDATED_DESCRIPTION = 'this is an updated description';
    const UPDATE_QUERY = gql`
      mutation RFIEdit($id: ID!, $input: [EditInput]!) {
        caseRfiEdit(id:$id, input:$input) {
          description
        }
      }
    `;
    const queryResult = await queryAsAnalyst({
      query: UPDATE_QUERY,
      variables: {
        id: rfiInternalId,
        input: [{ key: 'description', value: UPDATED_DESCRIPTION }],
      },
    });
    expect(queryResult?.data?.caseRfiEdit?.description)
      .toEqual(UPDATED_DESCRIPTION);
  });
  it('should not create without rbac', async () => {
    const IR_ID = 'case-rfi--01bd6fff-130a-4a49-88f9-f83f0bec84b5';
    const RFI_DATA = {
      input: {
        name: 'this should not work',
        stix_id: IR_ID,
      }
    };
    let data = await queryAsDefault({
      query: CREATE_QUERY,
      variables: RFI_DATA,
    });
    expect(data?.errors?.[0].message).toEqual("You are not allowed to do this.");
    expect(data.errors[0].name).toEqual("ForbiddenAccess");
    expect(data.errors[0].data?.http_status).toEqual(403);
    expect(data?.data?.caseRfiAdd).toBeNull();
    data = await queryAsDefault({
      query: READ_BY_ID,
      variables: { id: IR_ID },
    });
    expect(data?.data?.caseRfi).toBeNull();
  });
  it('should delete as analyst', async () => {
    const DELETE_QUERY = gql`
      mutation RFIDelete($id: ID!) {
        caseRfiDelete(id: $id)
      }
    `;
    await queryAsAnalyst({
      query: DELETE_QUERY,
      variables: { id: rfiInternalId },
    });
    // Verify rfi is no longer found
    const queryResult = await queryAsAnalyst({
      query: READ_BY_ID,
      variables: { id: rfiStixId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.caseRfi).toBeNull();
  });
});

describe('RFT resolver RBAC behavior', () => {
  let rftInternalId;
  const rftStixId = 'case-rft--41de54d0-f069-5686-a497-1b292096cb83';
  const RFT_NAME = 'Test RFT';

  const READ_ALL_QUERY = gql`
    query {
      caseRfts {
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

  const READ_BY_ID = gql`
    query ($id: String!) {
      caseRft(id: $id) {
        id
        standard_id
        name
        description
      }
    }
  `;

  const CREATE_QUERY = gql`
    mutation RFTAdd($input: CaseRftAddInput!) {
      caseRftAdd(input: $input) {
        id
        standard_id
        name
        description
      }
    }
  `;

  it('should create as analyst', async () => {
    const RFT_DATA = {
      input: {
        name: RFT_NAME,
        stix_id: rftStixId,
        description: 'A test rft',
      },
    };
    const data = await queryAsAnalyst({
      query: CREATE_QUERY,
      variables: RFT_DATA,
    });
    expect(data?.data?.caseRftAdd).not.toBeNull();
    expect(data.data.caseRftAdd.name).toEqual(RFT_NAME);
    rftInternalId = data.data.caseRftAdd.id;
  });
  it('should retrieve all as analyst', async () => {
    const queryResult = await queryAsAnalyst({
      query: READ_ALL_QUERY,
    });
    expect(queryResult?.data?.caseRfts).not.toBeNull();
    expect(queryResult.data.caseRfts.edges).not.toBeNull();
    expect(queryResult.data.caseRfts.edges.length).toBeGreaterThan(0);
  });
  it('should retrieve by internal id as analyst', async () => {
    const queryResult = await queryAsAnalyst({
      query: READ_BY_ID,
      variables: {
        id: rftInternalId,
      },
    });
    expect(queryResult?.data?.caseRft).not.toBeNull();
    expect(queryResult.data.caseRft.name).toEqual(RFT_NAME);
  });
  it('should retrieve by stix id as analyst', async () => {
    const queryResult = await queryAsAnalyst({
      query: READ_BY_ID,
      variables: {
        id: rftStixId,
      },
    });
    expect(queryResult?.data?.caseRft).not.toBeNull();
    expect(queryResult.data.caseRft.name).toEqual(RFT_NAME);
  });
  it('should update as analyst', async () => {
    const UPDATED_DESCRIPTION = 'this is an updated description';
    const UPDATE_QUERY = gql`
      mutation RFTEdit($id: ID!, $input: [EditInput]!) {
        caseRftEdit(id:$id, input:$input) {
          description
        }
      }
    `;
    const queryResult = await queryAsAnalyst({
      query: UPDATE_QUERY,
      variables: {
        id: rftInternalId,
        input: [{ key: 'description', value: UPDATED_DESCRIPTION }],
      },
    });
    expect(queryResult?.data?.caseRftEdit?.description)
      .toEqual(UPDATED_DESCRIPTION);
  });
  it('should not create without rbac', async () => {
    const IR_ID = 'case-rft--01bd6fff-130a-4a49-88f9-f83f0bec84b5';
    const RFT_DATA = {
      input: {
        name: 'this should not work',
        stix_id: IR_ID,
      }
    };
    let data = await queryAsDefault({
      query: CREATE_QUERY,
      variables: RFT_DATA,
    });
    expect(data?.errors?.[0].message).toEqual("You are not allowed to do this.");
    expect(data.errors[0].name).toEqual("ForbiddenAccess");
    expect(data.errors[0].data?.http_status).toEqual(403);
    expect(data?.data?.caseRftAdd).toBeNull();
    data = await queryAsDefault({
      query: READ_BY_ID,
      variables: { id: IR_ID },
    });
    expect(data?.data?.caseRft).toBeNull();
  });
  it('should delete as analyst', async () => {
    const DELETE_QUERY = gql`
      mutation RFTDelete($id: ID!) {
        caseRftDelete(id: $id)
      }
    `;
    await queryAsAnalyst({
      query: DELETE_QUERY,
      variables: { id: rftInternalId },
    });
    // Verify rft is no longer found
    const queryResult = await queryAsAnalyst({
      query: READ_BY_ID,
      variables: { id: rftStixId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.caseRft).toBeNull();
  });
});
