import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query dataSources(
    $first: Int
    $after: ID
    $orderBy: DataSourcesOrdering
    $orderMode: OrderingMode
    $filters: [DataSourcesFiltering!]
    $filterMode: FilterMode
    $search: String
  ) {
    dataSources(
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
  query dataSource($id: String!) {
    dataSource(id: $id) {
      id
      standard_id
      name
      description
      toStix
    }
  }
`;

describe('DataSource resolver standard behavior', () => {
  let dataSourceInternalId;
  const dataSourceStixId = 'data-source--934ab9db-49a9-4adb-9f1f-823d586928c0';
  it('should dataSource created', async () => {
    const CREATE_QUERY = gql`
      mutation DataSourceAdd($input: DataSourceAddInput!) {
        dataSourceAdd(input: $input) {
          id
          standard_id
          name
          description
        }
      }
    `;
    // Create the dataSource
    const DATA_COMPONENT_TO_CREATE = {
      input: {
        name: 'DataSource',
        stix_id: dataSourceStixId,
        description: 'DataSource description',
      },
    };
    const dataSource = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: DATA_COMPONENT_TO_CREATE,
    });
    expect(dataSource).not.toBeNull();
    expect(dataSource.data.dataSourceAdd).not.toBeNull();
    expect(dataSource.data.dataSourceAdd.name).toEqual('DataSource');
    dataSourceInternalId = dataSource.data.dataSourceAdd.id;
  });
  it('should dataSource loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: dataSourceInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.dataSource).not.toBeNull();
    expect(queryResult.data.dataSource.id).toEqual(dataSourceInternalId);
    expect(queryResult.data.dataSource.toStix.length).toBeGreaterThan(5);
  });
  it('should dataSource loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: dataSourceStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.dataSource).not.toBeNull();
    expect(queryResult.data.dataSource.id).toEqual(dataSourceInternalId);
  });
  it('should list dataSources', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.dataSources.edges.length).toEqual(1);
  });
  it('should update dataSource', async () => {
    const UPDATE_QUERY = gql`
      mutation DataSourceEdit($id: ID!, $input: [EditInput]!) {
        dataSourceFieldPatch(id: $id, input: $input) {
            id
            name
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: dataSourceInternalId, input: { key: 'name', value: ['DataSource - test'] } },
    });
    expect(queryResult.data.dataSourceFieldPatch.name).toEqual('DataSource - test');
  });
  it('should context patch dataSource', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation DataSourceEdit($id: ID!, $input: EditContext!) {
        dataSourceContextPatch(id: $id,  input: $input) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: dataSourceInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.dataSourceContextPatch.id).toEqual(dataSourceInternalId);
  });
  it('should context clean dataSource', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation DataSourceEdit($id: ID!, $input: EditContext!) {
        dataSourceContextPatch(id: $id,  input: $input) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: dataSourceInternalId, input: { focusOn: '' } },
    });
    expect(queryResult.data.dataSourceContextPatch.id).toEqual(dataSourceInternalId);
  });
  it('should dataSource deleted', async () => {
    const DELETE_QUERY = gql`
      mutation dataSourceDelete($id: ID!) {
        dataSourceDelete(id: $id)
      }
    `;
    // Delete the dataSource
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: dataSourceInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: dataSourceStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.dataSource).toBeNull();
  });
});
