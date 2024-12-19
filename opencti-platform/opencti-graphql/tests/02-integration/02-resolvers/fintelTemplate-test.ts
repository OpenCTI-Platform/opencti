import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { addFilter } from '../../../src/utils/filtering/filtering-utils';
import { activateEE, deactivateEE } from '../../utils/testEE';
import { adminQueryWithError } from '../../utils/testQueryHelper';
import { FORBIDDEN_ACCESS } from '../../../src/config/errors';
import { type FintelTemplateWidgetAddInput, WidgetPerspective } from '../../../src/generated/graphql';

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
        variable_name
        widget {
          type
          dataSelection {
            perspective
            filters
          }
          parameters {
            title
          }
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

const EDIT_QUERY = gql`
  mutation FintelTemplateEdit($id: ID!, $input: [EditInput!]!) {
    fintelTemplateFieldPatch(id: $id, input: $input) {
      id
      name
      description
      fintel_template_widgets {
        variable_name
        widget {
          type
          parameters {
            title
          }
        }
      }
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
  it('should fintel template edited', async () => {
    const queryResult = await queryAsAdmin({
      query: EDIT_QUERY,
      variables: {
        id: fintelTemplateInternalId,
        input: [{ key: 'description', value: ['new description'] }],
      }
    });
    const fintelTemplateDescription = queryResult.data?.fintelTemplateFieldPatch.description;
    expect(fintelTemplateDescription).toEqual('new description');
    const queryResult2 = await queryAsAdmin({ query: READ_QUERY, variables: { id: fintelTemplateInternalId } });
    expect(queryResult2.data?.fintelTemplate.description).toEqual('new description');
  });
  it('should add a fintel template widgets', async () => {
    const fintelTemplateWidgetAddInput: FintelTemplateWidgetAddInput = {
      variable_name: 'containerObservables',
      widget: {
        type: 'list',
        perspective: WidgetPerspective.Entities,
        dataSelection: [
          {
            perspective: WidgetPerspective.Entities,
            filters: JSON.stringify({
              mode: 'and',
              filters: [
                { key: ['entity_type'], values: ['Stix-Cyber-Observable'] },
                { key: ['objects'], values: ['SELF_ID'] },
              ],
              filterGroups: [],
            }),
            columns: [
              { label: 'Observable type', attribute: 'entity_type' },
              { label: 'Value', attribute: 'representative.main' },
            ],
          },
        ],
      },
    };
    const queryResult = await queryAsAdmin({
      query: EDIT_QUERY,
      variables: {
        id: fintelTemplateInternalId,
        input: [{ key: 'fintel_template_widgets', value: [fintelTemplateWidgetAddInput] }],
      }
    });
    const fintelTemplateWidgets = queryResult.data?.fintelTemplateFieldPatch.fintel_template_widgets;
    expect(fintelTemplateWidgets.length).toEqual(1);
    expect(fintelTemplateWidgets[0].variable_name).toEqual('containerObservables');
    expect(fintelTemplateWidgets[0].widget.type).toEqual('list');
    const queryResult2 = await queryAsAdmin({ query: READ_QUERY, variables: { id: fintelTemplateInternalId } });
    expect(queryResult2).not.toBeNull();
    expect(queryResult2.data?.fintelTemplate.fintel_template_widgets.length).toEqual(1);
    expect(queryResult2.data?.fintelTemplate.fintel_template_widgets[0].variable_name).toEqual('containerObservables');
    expect(queryResult2.data?.fintelTemplate.fintel_template_widgets[0].widget.type).toEqual('list');
    expect(queryResult2.data?.fintelTemplate.fintel_template_widgets[0].widget.dataSelection[0].perspective).toEqual(WidgetPerspective.Entities);
    expect(queryResult2.data?.fintelTemplate.fintel_template_widgets[0].widget.dataSelection[0].columns.length).toEqual(2);
  });
  it('should fintel template widget edited via object_path', async () => {
    const newWidget = {
      type: 'list',
      perspective: WidgetPerspective.Entities,
      dataSelection: [
        {
          perspective: WidgetPerspective.Entities,
          filters: JSON.stringify({
            mode: 'and',
            filters: [
              { key: ['entity_type'], values: ['Stix-Cyber-Observable'] },
              { key: ['objects'], values: ['SELF_ID'] },
            ],
            filterGroups: [],
          }),
          columns: [
            { label: 'Observable type', attribute: 'entity_type' },
            { label: 'Value', attribute: 'representative.main' },
            { label: 'Markings', attribute: 'objectMarking.definition' },
          ],
        },
      ],
      parameters: {
        title: 'Observables contained in the container',
      }
    };
    const queryResult = await queryAsAdmin({
      query: EDIT_QUERY,
      variables: {
        id: fintelTemplateInternalId,
        input: [{
          key: 'fintel_template_widgets',
          object_path: '/fintel_template_widgets/0/widget/',
          value: [newWidget]
        }],
      }
    });
    expect(queryResult.data?.fintelTemplateFieldPatch.fintel_template_widgets.length).toEqual(1);
    expect(queryResult.data?.fintelTemplateFieldPatch.fintel_template_widgets[0].widget.parameters.title).toEqual('Observables contained in the container');
    const queryResult2 = await queryAsAdmin({ query: READ_QUERY, variables: { id: fintelTemplateInternalId } });
    expect(queryResult2).not.toBeNull();
    expect(queryResult2.data?.fintelTemplate.fintel_template_widgets.length).toEqual(1);
    expect(queryResult2.data?.fintelTemplate.fintel_template_widgets[0].widget.type).toEqual('list');
    expect(queryResult2.data?.fintelTemplate.fintel_template_widgets[0].widget.parameters.title).toEqual('Observables contained in the container');
    expect(queryResult2.data?.fintelTemplate.fintel_template_widgets[0].widget.dataSelection[0].columns.length).toEqual(3);
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
    expect(queryResult.data?.fintelTemplate).toBeNull();
    // Deactivate EE
    await deactivateEE();
  });
});
