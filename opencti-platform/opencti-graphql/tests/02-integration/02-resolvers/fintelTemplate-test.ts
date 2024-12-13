import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { addFilter } from '../../../src/utils/filtering/filtering-utils';
import { activateEE, deactivateEE } from '../../utils/testEE';
import { adminQueryWithError } from '../../utils/testQueryHelper';
import { FORBIDDEN_ACCESS } from '../../../src/config/errors';

const FINTEL_TEMPLATE_SETTINGS_LIST_QUERY = gql`
  query entitySettings(
    $filters: FilterGroup
  ) {
    entitySettings(
      filters: $filters
    ) {
      edges {
        node {
          id
          target_type
          fintelTemplates {
            edges {
              node {
                id
                name
                settings_types
              }
            }
          }
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query fintelTemplate($id: ID!) {
    fintelTemplate(id: $id) {
      id
      standard_id
      name
      description
      content
      instance_filters
      settings_types
      start_date
      fintel_template_widgets {
        id
        variable_name
        widget {
          id
        }
      }
    }
  }
`;

const CREATE_QUERY = gql`
  mutation FintelTemplateAdd($input: FintelTemplateAddInput!) {
    fintelTemplateAdd(input: $input) {
      id
      name
      description
    }
  }
`;

describe('Fintel template resolver standard behavior', () => {
  let fintelTemplateInternalId: string;
  const FINTEL_TEMPLATE_TO_CREATE = {
    input: {
      name: 'Fintel template 1',
      description: 'My fintel template description',
      start_date: '2025-01-01T19:00:05.000Z',
      settings_types: ['Report']
    },
  };
  it('should not create fintel template if not EE', async () => {
    await adminQueryWithError(
      {
        query: CREATE_QUERY,
        variables: FINTEL_TEMPLATE_TO_CREATE,
      },
      'You are not allowed to do this.',
      FORBIDDEN_ACCESS
    );
  });
  it('should fintel template created', async () => {
    // Activate EE
    await activateEE();
    // Create the fintel template
    const fintelTemplate = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: FINTEL_TEMPLATE_TO_CREATE,
    });
    expect(fintelTemplate).not.toBeNull();
    expect(fintelTemplate.data?.fintelTemplateAdd).not.toBeNull();
    expect(fintelTemplate.data?.fintelTemplateAdd.name).toEqual('Fintel template 1');
    fintelTemplateInternalId = fintelTemplate.data?.fintelTemplateAdd.id;
  });
  it('should fintel template loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: fintelTemplateInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.fintelTemplate).not.toBeNull();
    expect(queryResult.data?.fintelTemplate.id).toEqual(fintelTemplateInternalId);
    expect(queryResult.data?.fintelTemplate.name).toEqual('Fintel template 1');
    expect(queryResult.data?.fintelTemplate.fintel_template_widgets.length).toEqual(0);
  });
  it('should list fintel templates in entity settings', async () => {
    const queryResult = await queryAsAdmin({
      query: FINTEL_TEMPLATE_SETTINGS_LIST_QUERY,
      variables: { filters: addFilter(undefined, 'target_type', ['Report']) },
    });
    const fintelTemplatesEdges = queryResult.data?.entitySettings.edges[0].node.fintelTemplates.edges;
    expect(fintelTemplatesEdges.length).toEqual(1);
    expect(fintelTemplatesEdges[0].node.id).toEqual(fintelTemplateInternalId);
    const queryResult2 = await queryAsAdmin({
      query: FINTEL_TEMPLATE_SETTINGS_LIST_QUERY,
      variables: { filters: addFilter(undefined, 'target_type', ['Grouping']) },
    });
    const fintelTemplatesEdges2 = queryResult2.data?.entitySettings.edges[0].node.fintelTemplates.edges;
    expect(fintelTemplatesEdges2.length).toEqual(0);
  });
  it('should fintel template deleted', async () => {
    const DELETE_QUERY = gql`
      mutation fintelTemplateDelete($id: ID!) {
        fintelTemplateDelete(id: $id)
      }
    `;
    // Delete the fintel template
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: fintelTemplateInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: fintelTemplateInternalId } });
    expect(queryResult).not.toBeNull();
    const queryResult2 = await queryAsAdmin({
      query: FINTEL_TEMPLATE_SETTINGS_LIST_QUERY,
      variables: { filters: addFilter(undefined, 'target_type', ['Report']) },
    });
    const fintelTemplatesEdges2 = queryResult2.data?.entitySettings.edges[0].node.fintelTemplates.edges;
    expect(fintelTemplatesEdges2.length).toEqual(0);
    // Deactivate EE
    await deactivateEE();
  });
});
