import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { adminQueryWithError, adminQueryWithSuccess } from '../../utils/testQueryHelper';
import type { PlaybookAddNodeInput } from '../../../src/generated/graphql';
import { PLAYBOOK_INTERNAL_DATA_CRON, PLAYBOOK_MATCHING_COMPONENT } from '../../../src/modules/playbook/playbook-components';
import { UNSUPPORTED_ERROR } from '../../../src/config/errors';

const LIST_PLAYBOOKS = gql`
  query playbooks(
    $first: Int
    $after: ID
    $orderBy: PlaybooksOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    playbooks(
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
        }
      }
    }
  }
`;

const CREATE_PLAYBOOK = gql`
  mutation playbookAdd($input: PlaybookAddInput!) {
    playbookAdd(input: $input){
      id
      name
    }
  }
`;

const READ_PLAYBOOK = gql`
  query playbook($id: String!) {
    playbook(id: $id) {
      id
      name
      description
      playbook_running
      playbook_definition
    }
  }
`;

const UPDATE_PLAYBOOK = gql`
  mutation playbookFieldPatchEdit($id: ID!, $input: [EditInput!]!) {
    playbookFieldPatch(id: $id, input: $input) {
      id
      name
    }
  }
`;

const ADD_NODE_PLAYBOOK = gql`
    mutation playbookAddNode($id: ID!, $input: PlaybookAddNodeInput!) {
        playbookAddNode(id: $id, input: $input)
    }
`;

const DELETE_PLAYBOOK = gql`
  mutation playbookDelete($id: ID!) {
    playbookDelete(id:$id)
  }
`;

describe('Playbook resolver standard behavior', () => {
  let playbookId = '';
  const playbookName = 'Playbook1';
  it('should list playbooks', async () => {
    const queryResult = await adminQueryWithSuccess({ query: LIST_PLAYBOOKS, variables: { first: 10 } });
    expect(queryResult.data?.playbooks.edges.length).toEqual(0);
  });
  it('should add playbook', async () => {
    const input = {
      input: {
        name: playbookName,
      }
    };
    const queryResult = await adminQueryWithSuccess({
      query: CREATE_PLAYBOOK,
      variables: input,
    });
    expect(queryResult.data?.playbookAdd.name).toEqual(playbookName);
    playbookId = queryResult.data?.playbookAdd.id;
  });
  it('should list playbooks', async () => {
    const queryResult = await adminQueryWithSuccess({ query: LIST_PLAYBOOKS, variables: { first: 10 } });
    expect(queryResult.data?.playbooks.edges.length).toEqual(1);
  });
  it('should read playbook', async () => {
    const queryResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
    expect(queryResult.data?.playbook.name).toEqual(playbookName);
    expect(queryResult.data?.playbook.playbook_running).toEqual(false);
  });
  it('should update playbook', async () => {
    const queryResult = await adminQueryWithSuccess({
      query: UPDATE_PLAYBOOK,
      variables: {
        id: playbookId,
        input: [
          { key: 'name', value: ['Playbook1 - updated'] },
        ]
      }
    });
    expect(queryResult.data?.playbookFieldPatch.name).toEqual('Playbook1 - updated');
  });
  it('should add entry node to a playbook', async () => {
    const emptyStringFilters = JSON.stringify({
      mode: 'and',
      filters: [
        { key: ['entity_type'], values: ['Report'], operator: 'eq' },
      ],
      filterGroups: [],
    });
    const configuration = {
      filters: emptyStringFilters,
    };
    const addNodeInput: PlaybookAddNodeInput = {
      component_id: PLAYBOOK_INTERNAL_DATA_CRON.id,
      configuration: JSON.stringify(configuration),
      name: 'node1',
      position: {
        x: 3,
        y: 12,
      },
    };
    await adminQueryWithSuccess({
      query: ADD_NODE_PLAYBOOK,
      variables: {
        id: playbookId,
        input: addNodeInput,
      }
    });
    const queryResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
    const playbookNodes = JSON.parse(queryResult.data?.playbook.playbook_definition).nodes;
    expect(playbookNodes.length).toEqual(1);
    const node1 = playbookNodes[0];
    expect(node1.name).toEqual('node1');
    expect(node1.position.x).toEqual(3);
    expect(JSON.parse(node1.configuration).filters).toEqual(emptyStringFilters);
  });
  it('should not add several entry nodes to a playbook', async () => {
    const emptyStringFilters = JSON.stringify({
      mode: 'and',
      filters: [],
      filterGroups: [],
    });
    const configuration = {
      filters: emptyStringFilters,
    };
    const addNodeInput: PlaybookAddNodeInput = {
      component_id: PLAYBOOK_INTERNAL_DATA_CRON.id,
      configuration: JSON.stringify(configuration),
      name: 'node1',
      position: {
        x: 3,
        y: 12,
      },
    };
    await adminQueryWithError(
      {
        query: ADD_NODE_PLAYBOOK,
        variables: {
          id: playbookId,
          input: addNodeInput,
        }
      },
      'Playbook multiple entrypoint is not supported',
      UNSUPPORTED_ERROR
    );
  });
  it('should not add node with incorrect filters for PLAYBOOK_INTERNAL_DATA_CRON component', async () => {
    const incorrectStringFilters = JSON.stringify({
      mode: 'and',
      filters: [
        { key: ['fake_key'], values: [], operator: 'nil' },
      ],
      filterGroups: [],
    });
    const configuration = {
      filters: incorrectStringFilters,
    };
    const addNodeInput: PlaybookAddNodeInput = {
      component_id: PLAYBOOK_INTERNAL_DATA_CRON.id,
      configuration: JSON.stringify(configuration),
      name: 'incorrectNode',
      position: { x: 1, y: 1 },
    };
    await adminQueryWithError(
      {
        query: ADD_NODE_PLAYBOOK,
        variables: {
          id: playbookId,
          input: addNodeInput,
        }
      },
      'incorrect filter keys not existing in any schema definition',
      UNSUPPORTED_ERROR
    );
  });
  it('should not add node with incorrect filters for components with stix filtering', async () => {
    const incorrectStringFilters = JSON.stringify({
      mode: 'and',
      filters: [
        { key: ['published'], values: [], operator: 'nil' },
      ],
      filterGroups: [],
    });
    const configuration = {
      filters: incorrectStringFilters,
    };
    const addNodeInput: PlaybookAddNodeInput = {
      component_id: PLAYBOOK_MATCHING_COMPONENT.id,
      configuration: JSON.stringify(configuration),
      name: 'incorrectNode',
      position: { x: 1, y: 1 },
    };
    await adminQueryWithError(
      {
        query: ADD_NODE_PLAYBOOK,
        variables: {
          id: playbookId,
          input: addNodeInput,
        }
      },
      'Stix filtering is not compatible with the provided filter key',
      UNSUPPORTED_ERROR
    );
  });
  it('should remove playbook', async () => {
    const queryResult = await adminQueryWithSuccess({
      query: DELETE_PLAYBOOK,
      variables: { id: playbookId },
    });
    expect(queryResult.data?.playbookDelete).toEqual(playbookId);
  });
});
