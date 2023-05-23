import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

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
