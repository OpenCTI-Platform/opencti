import { expect, it, describe, vi, beforeAll } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQueryHelper';
import * as entrepriseEdition from '../../../src/enterprise-edition/ee';

const LIST_QUERY = gql`
  query fintelDesigns(
    $first: Int
    $after: ID
    $orderBy: FintelDesignOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    fintelDesigns(
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
          name
          default
          description
          file_id
          gradiantFromColor
          gradiantToColor
          textColor
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query fintelDesign($id: String!) {
    fintelDesign(id: $id) {
      id
      standard_id
      name
      description
      file_id
      gradiantFromColor
      gradiantToColor
      textColor
    }
  }
`;

const CREATE_QUERY = gql`
  mutation fintelDesignAdd($input: FintelDesignAddInput!) {
    fintelDesignAdd(input: $input) {
      id
      name
      description
    }
  }
`;

const EDIT_QUERY = gql`
  mutation FintelDesignEdit($id: ID!, $input: [EditInput!], $file: Upload) {
    fintelDesignFieldPatch(id: $id, input: $input, file: $file) {
      id
      name
      description
      file_id
      textColor
      gradiantToColor
      gradiantFromColor
    }
  }
`;

describe('Fintel Design resolver standard behavior', () => {
  let fintelDesignInternalId: string;
  const fintelDesignInput = {
    name: 'Test Fintel Design',
    description: 'A design for testing',
    gradiantFromColor: '#ffffff',
    gradiantToColor: '#000000',
    textColor: '#333333',
  };
  let secondFintelDesignInternalId: string;

  beforeAll(() => {
    // Activate EE for this test
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
  });

  it('should create Fintel Design', async () => {
    // Create fintel design
    const fintelDesign = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: { input: fintelDesignInput },
    });
    expect(fintelDesign).not.toBeNull();
    expect(fintelDesign.data?.fintelDesignAdd).not.toBeNull();
    expect(fintelDesign.data?.fintelDesignAdd.name).toEqual('Test Fintel Design');
    fintelDesignInternalId = fintelDesign.data?.fintelDesignAdd.id;
  });

  it('should fintel design loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: fintelDesignInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.fintelDesign).not.toBeNull();
    expect(queryResult.data?.fintelDesign.id).toEqual(fintelDesignInternalId);
    expect(queryResult.data?.fintelDesign.name).toEqual('Test Fintel Design');
  });

  it('should list Fintel Designs', async () => {
    const listResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(listResult.data?.fintelDesigns.edges.length).toBeGreaterThan(0);
  });

  it('should enforce unique default Fintel Design', async () => {
    await queryAsAdmin({
      query: EDIT_QUERY,
      variables: {
        id: fintelDesignInternalId,
        input: [{ key: 'default', value: ['true'] }],
      },
    });

    const secondDesign = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: {
        input: {
          ...fintelDesignInput,
          name: 'Test Fintel Design 2',
          default: true,
        },
      },
    });
    secondFintelDesignInternalId = secondDesign.data?.fintelDesignAdd.id;

    const listResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 50 } });
    const firstDesign = listResult.data?.fintelDesigns.edges.find((e: { node: { id: string } }) => e.node.id === fintelDesignInternalId)?.node;
    const secondDesignFromList = listResult.data?.fintelDesigns.edges.find((e: { node: { id: string } }) => e.node.id === secondFintelDesignInternalId)?.node;
    expect(firstDesign?.default).toEqual(false);
    expect(secondDesignFromList?.default).toEqual(true);
  });

  it('should update Fintel Design', async () => {
    // update fintel design
    const updateResult = await queryAsAdmin({
      query: EDIT_QUERY,
      variables: {
        id: fintelDesignInternalId,
        input: [{ key: 'name', value: ['Updated Fintel Design'] }],
      },
    });
    const fintelDesignName = updateResult.data?.fintelDesignFieldPatch.name;
    expect(fintelDesignName).toEqual('Updated Fintel Design');
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: fintelDesignInternalId } });
    expect(queryResult.data?.fintelDesign.name).toEqual('Updated Fintel Design');
  });

  it('should delete FintelDesign', async () => {
    // delete fintel design
    const DELETE_QUERY = gql`
      mutation FintelDesignDelete($id: ID!) {
        fintelDesignDelete(id: $id)
      }
    `;
    await queryAsAdmin({ query: DELETE_QUERY, variables: { id: fintelDesignInternalId } });
    if (secondFintelDesignInternalId) {
      await queryAsAdmin({ query: DELETE_QUERY, variables: { id: secondFintelDesignInternalId } });
    }
    const readAfterDelete = await queryAsAdmin({ query: READ_QUERY, variables: { id: fintelDesignInternalId } });
    expect(readAfterDelete).not.toBeNull();
    expect(readAfterDelete.data?.fintelDesign).toBeNull();
  });
});
