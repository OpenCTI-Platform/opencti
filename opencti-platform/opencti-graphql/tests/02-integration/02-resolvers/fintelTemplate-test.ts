import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { addFilter } from '../../../src/utils/filtering/filtering-utils';
import { disableEE, enableEE } from '../../utils/testQueryHelper';
import { type FintelTemplateWidgetAddInput, WidgetPerspective } from '../../../src/generated/graphql';
import { SELF_ID } from '../../../src/utils/fintelTemplate/__fintelTemplateWidgets';

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
      template_content
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
            columns {
              variableName
              label
              attribute
            }
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
          dataSelection {
            perspective
            filters
            columns {
              variableName
              label
              attribute
            }
          }
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
  it('should fintel template created', async () => {
    // Activate EE
    await enableEE();
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
  });
  it('should fintel template created with built-in attributes widget for self instance', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: fintelTemplateInternalId } });
    expect(queryResult.data?.fintelTemplate.fintel_template_widgets.length).toEqual(4); // the 4 built-in widgets
    expect(queryResult.data?.fintelTemplate.fintel_template_widgets[0].variable_name).toEqual('widgetSelfAttributes');
    expect(queryResult.data?.fintelTemplate.fintel_template_widgets[1].variable_name).toEqual('observables');
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
                { key: ['objects'], values: [SELF_ID] },
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
        input: [{ key: 'fintel_template_widgets', object_path: 'fintel_template_widgets/1', value: [fintelTemplateWidgetAddInput] }],
      }
    });
    const fintelTemplateWidgets = queryResult.data?.fintelTemplateFieldPatch.fintel_template_widgets;
    expect(fintelTemplateWidgets.length).toEqual(2); // the added one and the built-in
    expect(fintelTemplateWidgets[1].variable_name).toEqual('containerObservables');
    expect(fintelTemplateWidgets[1].widget.type).toEqual('list');
    const queryResult2 = await queryAsAdmin({ query: READ_QUERY, variables: { id: fintelTemplateInternalId } });
    expect(queryResult2).not.toBeNull();
    expect(queryResult2.data?.fintelTemplate.fintel_template_widgets.length).toEqual(2);
    expect(queryResult2.data?.fintelTemplate.fintel_template_widgets[1].variable_name).toEqual('containerObservables');
    expect(queryResult2.data?.fintelTemplate.fintel_template_widgets[1].widget.type).toEqual('list');
    expect(queryResult2.data?.fintelTemplate.fintel_template_widgets[1].widget.dataSelection[0].perspective).toEqual(WidgetPerspective.Entities);
    expect(queryResult2.data?.fintelTemplate.fintel_template_widgets[1].widget.dataSelection[0].columns.length).toEqual(2);
  });
  it('should check fintel template widgets variable names: variable names are mandatory for every column in attribute widgets', async () => {
    const fintelTemplateAttributeWidgetAddInput: FintelTemplateWidgetAddInput = {
      variable_name: 'MyAttributes',
      widget: {
        type: 'attribute',
        perspective: WidgetPerspective.Entities,
        dataSelection: [
          {
            perspective: WidgetPerspective.Entities,
            columns: [
              { label: 'Entity type', attribute: 'entity_type' },
              { label: 'Representative', attribute: 'representative.main' },
            ],
          },
        ],
      },
    };
    const attributeQueryResult = await queryAsAdmin({
      query: EDIT_QUERY,
      variables: {
        id: fintelTemplateInternalId,
        input: [{ key: 'fintel_template_widgets', value: [fintelTemplateAttributeWidgetAddInput], operation: 'add' }],
      }
    });
    expect(attributeQueryResult.errors?.length).toBe(1);
    expect(attributeQueryResult.errors?.[0].message).toEqual('Attributes should all have a variable name');
  });
  it('should check fintel template widgets variable names: no spaces and no special characters', async () => {
    // list widget
    const fintelTemplateWidgetAddInput: FintelTemplateWidgetAddInput = {
      variable_name: 'container of observables',
      widget: {
        type: 'list',
        perspective: WidgetPerspective.Entities,
        dataSelection: [
          {
            perspective: WidgetPerspective.Entities,
          },
        ],
      },
    };
    const queryResult = await queryAsAdmin({
      query: EDIT_QUERY,
      variables: {
        id: fintelTemplateInternalId,
        input: [{ key: 'fintel_template_widgets', value: [fintelTemplateWidgetAddInput], operation: 'add' }],

      }
    });
    expect(queryResult.errors?.length).toBe(1);
    expect(queryResult.errors?.[0].message).toEqual('Variable names should not contain spaces or special chars (except - and _)');
    // attribute widget
    const fintelTemplateAttributeWidgetAddInput: FintelTemplateWidgetAddInput = {
      variable_name: 'MyAttributes',
      widget: {
        type: 'attribute',
        perspective: WidgetPerspective.Entities,
        dataSelection: [
          {
            perspective: WidgetPerspective.Entities,
            columns: [
              { label: 'Entity type', attribute: 'entity_type', variableName: 'EntityType' },
              { label: 'Representative', attribute: 'representative.main', variableName: '$representative' },
            ],
          },
        ],
      },
    };
    const attributeQueryResult = await queryAsAdmin({
      query: EDIT_QUERY,
      variables: {
        id: fintelTemplateInternalId,
        input: [{ key: 'fintel_template_widgets', value: [fintelTemplateAttributeWidgetAddInput], operation: 'add' }],
      }
    });
    expect(attributeQueryResult.errors?.length).toBe(1);
    expect(attributeQueryResult.errors?.[0].message).toEqual('Variable names should not contain spaces or special chars (except - and _)');
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
    await disableEE();
  });
});
