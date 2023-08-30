import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query dataComponents(
    $first: Int
    $after: ID
    $orderBy: DataComponentsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $filterMode: FilterMode
    $search: String
  ) {
    dataComponents(
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
  query dataComponent($id: String!) {
    dataComponent(id: $id) {
      id
      standard_id
      name
      description
      toStix
    }
  }
`;

describe('DataComponent resolver standard behavior', () => {
  let dataComponentInternalId;
  const dataComponentStixId = 'data-component--934ab9db-49a9-4adb-9f1f-823d586928c0';
  it('should dataComponent created', async () => {
    const CREATE_QUERY = gql`
      mutation DataComponentAdd($input: DataComponentAddInput!) {
        dataComponentAdd(input: $input) {
          id
          standard_id
          name
          description
        }
      }
    `;
    // Create the dataComponent
    const DATA_COMPONENT_TO_CREATE = {
      input: {
        name: 'DataComponent',
        stix_id: dataComponentStixId,
        description: 'DataComponent description',
      },
    };
    const dataComponent = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: DATA_COMPONENT_TO_CREATE,
    });
    expect(dataComponent).not.toBeNull();
    expect(dataComponent.data.dataComponentAdd).not.toBeNull();
    expect(dataComponent.data.dataComponentAdd.name).toEqual('DataComponent');
    dataComponentInternalId = dataComponent.data.dataComponentAdd.id;
  });
  it('should dataComponent loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: dataComponentInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.dataComponent).not.toBeNull();
    expect(queryResult.data.dataComponent.id).toEqual(dataComponentInternalId);
    expect(queryResult.data.dataComponent.toStix.length).toBeGreaterThan(5);
  });
  it('should dataComponent loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: dataComponentStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.dataComponent).not.toBeNull();
    expect(queryResult.data.dataComponent.id).toEqual(dataComponentInternalId);
  });
  it('should list dataComponents', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.dataComponents.edges.length).toEqual(1);
  });
  it('should update dataComponent', async () => {
    const UPDATE_QUERY = gql`
      mutation DataComponentEdit($id: ID!, $input: [EditInput]!) {
        dataComponentFieldPatch(id: $id, input: $input) {
            id
            name
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: dataComponentInternalId, input: { key: 'name', value: ['DataComponent - test'] } },
    });
    expect(queryResult.data.dataComponentFieldPatch.name).toEqual('DataComponent - test');
  });
  it('should context patch dataComponent', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation DataComponentEdit($id: ID!, $input: EditContext!) {
        dataComponentContextPatch(id: $id,  input: $input) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: dataComponentInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.dataComponentContextPatch.id).toEqual(dataComponentInternalId);
  });
  it('should context clean dataComponent', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation DataComponentEdit($id: ID!, $input: EditContext!) {
        dataComponentContextPatch(id: $id,  input: $input) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: dataComponentInternalId, input: { focusOn: '' } },
    });
    expect(queryResult.data.dataComponentContextPatch.id).toEqual(dataComponentInternalId);
  });
  it('should dataComponent deleted', async () => {
    const DELETE_QUERY = gql`
      mutation dataComponentDelete($id: ID!) {
        dataSourceDelete(id: $id)
      }
    `;
    // Delete the dataComponent
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: dataComponentInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: dataComponentStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.dataComponent).toBeNull();
  });
});
