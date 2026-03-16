import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { adminQueryWithError, adminQueryWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import type { PlaybookAddLinkInput, PlaybookAddNodeInput } from '../../../src/generated/graphql';
import { PLAYBOOK_INTERNAL_DATA_CRON, PLAYBOOK_MATCHING_COMPONENT } from '../../../src/modules/playbook/playbook-components';
import { UNSUPPORTED_ERROR } from '../../../src/config/errors';
import { USER_PARTICIPATE, USER_SECURITY } from '../../utils/testQuery';

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

const REPLACE_NODE_PLAYBOOK = gql`
    mutation playbookReplaceNode($id: ID!, $nodeId: ID!, $input: PlaybookAddNodeInput!) {
        playbookReplaceNode(id: $id, nodeId: $nodeId, input: $input)
    }
`;

const ADD_LINK_PLAYBOOK = gql`
    mutation playbookAddLink($id: ID!, $input: PlaybookAddLinkInput!) {
        playbookAddLink(id: $id, input: $input)
    }
`;

const DELETE_NODE_PLAYBOOK = gql`
    mutation playbookDeleteNode($id: ID!, $nodeId: ID!) {
        playbookDeleteNode(id: $id, nodeId: $nodeId) {
            id
        }
    }
`;

const DELETE_LINK_PLAYBOOK = gql`
    mutation playbookDeleteLink($id: ID!, $linkId: ID!) {
        playbookDeleteLink(id: $id, linkId: $linkId) {
            id
        }
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
  const emptyStringFilters = JSON.stringify({
    mode: 'and',
    filters: [
      { key: ['entity_type'], values: ['Report'], operator: 'eq' },
    ],
    filterGroups: [],
  });
  it('should list playbooks', async () => {
    const queryResult = await adminQueryWithSuccess({ query: LIST_PLAYBOOKS, variables: { first: 10 } });
    expect(queryResult.data?.playbooks.edges.length).toEqual(0);
  });
  it('should not add playbook if no Manage Playbooks capability', async () => {
    const input = {
      input: {
        name: playbookName,
      },
    };
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
      query: CREATE_PLAYBOOK,
      variables: input,
    });
  });
  it('should add playbook with Manage Playbooks capability', async () => {
    const input = {
      input: {
        name: playbookName,
      },
    };
    const queryResult = await queryAsUserWithSuccess(USER_SECURITY.client, {
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
  it('should not update playbook if no Manage Playbooks capability', async () => {
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
      query: UPDATE_PLAYBOOK,
      variables: {
        id: playbookId,
        input: [
          { key: 'name', value: ['Playbook1 - updated'] },
        ],
      },
    });
  });
  it('should update playbook with Manage Playbooks capability', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_SECURITY.client, {
      query: UPDATE_PLAYBOOK,
      variables: {
        id: playbookId,
        input: [
          { key: 'name', value: ['Playbook1 - updated'] },
        ],
      },
    });
    expect(queryResult.data?.playbookFieldPatch.name).toEqual('Playbook1 - updated');
  });
  describe('playbookAddNode', () => {
    it('should add entry node to a playbook', async () => {
      // ...existing test body...
      const configuration = {
        filters: emptyStringFilters,
      };
      const addNodeInput: PlaybookAddNodeInput = {
        component_id: PLAYBOOK_INTERNAL_DATA_CRON.id,
        configuration: JSON.stringify(configuration),
        name: 'node1',
        position: {
          x: 1,
          y: 1,
        },
      };
      await adminQueryWithSuccess({
        query: ADD_NODE_PLAYBOOK,
        variables: {
          id: playbookId,
          input: addNodeInput,
        },
      });
      const queryResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const playbookNodes = JSON.parse(queryResult.data?.playbook.playbook_definition).nodes;
      expect(playbookNodes.length).toEqual(1);
      const node1 = playbookNodes[0];
      expect(node1.name).toEqual('node1');
      expect(node1.position.x).toEqual(1);
      expect(JSON.parse(node1.configuration).filters).toEqual(emptyStringFilters);
    });
    it('should not add several entry nodes to a playbook', async () => {
      const configuration = {
        filters: emptyStringFilters,
      };
      const addNodeInput: PlaybookAddNodeInput = {
        component_id: PLAYBOOK_INTERNAL_DATA_CRON.id,
        configuration: JSON.stringify(configuration),
        name: 'node1',
        position: {
          x: 1,
          y: 2,
        },
      };
      await adminQueryWithError(
        {
          query: ADD_NODE_PLAYBOOK,
          variables: {
            id: playbookId,
            input: addNodeInput,
          },
        },
        'Playbook multiple entrypoint is not supported',
        UNSUPPORTED_ERROR,
      );
    });
    it('should not add unknown component to a playbook', async () => {
      const configuration = {
        filters: emptyStringFilters,
      };
      const addNodeInput: PlaybookAddNodeInput = {
        component_id: 'fake_component_id',
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
          },
        },
        'Playbook related component not found',
        UNSUPPORTED_ERROR,
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
          },
        },
        'Incorrect filter keys not existing in any schema definition',
        UNSUPPORTED_ERROR,
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
          },
        },
        'Stix filtering is not compatible with the provided filter key',
        UNSUPPORTED_ERROR,
      );
    });
  });
  describe('playbookReplaceNode', () => {
    it('should replace an existing node in the playbook', async () => {
      // First, get the current playbook definition to find the node id
      const readResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const playbookNodes = JSON.parse(readResult.data?.playbook.playbook_definition).nodes;
      expect(playbookNodes.length).toEqual(1);
      const existingNodeId = playbookNodes[0].id;

      // Replace the existing entry node with updated name and position
      const configuration = {
        filters: emptyStringFilters,
      };
      const replaceNodeInput: PlaybookAddNodeInput = {
        component_id: PLAYBOOK_INTERNAL_DATA_CRON.id,
        configuration: JSON.stringify(configuration),
        name: 'node1-replaced',
        position: {
          x: 10,
          y: 20,
        },
      };
      const replaceResult = await adminQueryWithSuccess({
        query: REPLACE_NODE_PLAYBOOK,
        variables: {
          id: playbookId,
          nodeId: existingNodeId,
          input: replaceNodeInput,
        },
      });
      expect(replaceResult.data?.playbookReplaceNode).toEqual(existingNodeId);

      // Verify the node was replaced correctly
      const verifyResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const updatedNodes = JSON.parse(verifyResult.data?.playbook.playbook_definition).nodes;
      expect(updatedNodes.length).toEqual(1);
      const replacedNode = updatedNodes[0];
      expect(replacedNode.id).toEqual(existingNodeId);
      expect(replacedNode.name).toEqual('node1-replaced');
      expect(replacedNode.position.x).toEqual(10);
      expect(replacedNode.position.y).toEqual(20);
      expect(replacedNode.component_id).toEqual(PLAYBOOK_INTERNAL_DATA_CRON.id);
    });
    it('should not replace a node with an unknown component', async () => {
      const readResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const playbookNodes = JSON.parse(readResult.data?.playbook.playbook_definition).nodes;
      const existingNodeId = playbookNodes[0].id;

      const replaceNodeInput: PlaybookAddNodeInput = {
        component_id: 'fake_component_id',
        configuration: JSON.stringify({ filters: emptyStringFilters }),
        name: 'bad-node',
        position: { x: 1, y: 1 },
      };
      await adminQueryWithError(
        {
          query: REPLACE_NODE_PLAYBOOK,
          variables: {
            id: playbookId,
            nodeId: existingNodeId,
            input: replaceNodeInput,
          },
        },
        'Playbook related component not found',
        UNSUPPORTED_ERROR,
      );
    });
    it('should not replace a node with incorrect filters', async () => {
      const readResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const playbookNodes = JSON.parse(readResult.data?.playbook.playbook_definition).nodes;
      const existingNodeId = playbookNodes[0].id;

      const incorrectStringFilters = JSON.stringify({
        mode: 'and',
        filters: [
          { key: ['fake_key'], values: [], operator: 'nil' },
        ],
        filterGroups: [],
      });
      const replaceNodeInput: PlaybookAddNodeInput = {
        component_id: PLAYBOOK_INTERNAL_DATA_CRON.id,
        configuration: JSON.stringify({ filters: incorrectStringFilters }),
        name: 'bad-filters-node',
        position: { x: 1, y: 1 },
      };
      await adminQueryWithError(
        {
          query: REPLACE_NODE_PLAYBOOK,
          variables: {
            id: playbookId,
            nodeId: existingNodeId,
            input: replaceNodeInput,
          },
        },
        'Incorrect filter keys not existing in any schema definition',
        UNSUPPORTED_ERROR,
      );
    });
    it('should not replace a node if no Manage Playbooks capability', async () => {
      const readResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const playbookNodes = JSON.parse(readResult.data?.playbook.playbook_definition).nodes;
      const existingNodeId = playbookNodes[0].id;

      const replaceNodeInput: PlaybookAddNodeInput = {
        component_id: PLAYBOOK_INTERNAL_DATA_CRON.id,
        configuration: JSON.stringify({ filters: emptyStringFilters }),
        name: 'forbidden-replace',
        position: { x: 1, y: 1 },
      };
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
        query: REPLACE_NODE_PLAYBOOK,
        variables: {
          id: playbookId,
          nodeId: existingNodeId,
          input: replaceNodeInput,
        },
      });
    });
  });
  describe('playbookAddLink', () => {
    let secondNodeId = '';
    it('should add a second (non-entry) node to prepare link tests', async () => {
      const configuration = {
        filters: emptyStringFilters,
      };
      const addNodeInput: PlaybookAddNodeInput = {
        component_id: PLAYBOOK_MATCHING_COMPONENT.id,
        configuration: JSON.stringify(configuration),
        name: 'matching-node',
        position: { x: 5, y: 5 },
      };
      const addResult = await adminQueryWithSuccess({
        query: ADD_NODE_PLAYBOOK,
        variables: {
          id: playbookId,
          input: addNodeInput,
        },
      });
      secondNodeId = addResult.data?.playbookAddNode;
      expect(secondNodeId).toBeDefined();

      // Verify both nodes exist
      const readResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const playbookNodes = JSON.parse(readResult.data?.playbook.playbook_definition).nodes;
      expect(playbookNodes.length).toEqual(2);
    });
    it('should add a link between two nodes', async () => {
      const readResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const playbookDef = JSON.parse(readResult.data?.playbook.playbook_definition);
      const entryNodeId = playbookDef.nodes.find((n: any) => n.component_id === PLAYBOOK_INTERNAL_DATA_CRON.id).id;

      const addLinkInput: PlaybookAddLinkInput = {
        from_node: entryNodeId,
        from_port: 'out',
        to_node: secondNodeId,
      };
      const linkResult = await adminQueryWithSuccess({
        query: ADD_LINK_PLAYBOOK,
        variables: {
          id: playbookId,
          input: addLinkInput,
        },
      });
      const linkId = linkResult.data?.playbookAddLink;
      expect(linkId).toBeDefined();

      // Verify the link was created correctly
      const verifyResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const updatedDef = JSON.parse(verifyResult.data?.playbook.playbook_definition);
      expect(updatedDef.links.length).toEqual(1);
      const link = updatedDef.links[0];
      expect(link.id).toEqual(linkId);
      expect(link.from.id).toEqual(entryNodeId);
      expect(link.from.port).toEqual('out');
      expect(link.to.id).toEqual(secondNodeId);
    });
    it('should not add a duplicate link', async () => {
      const readResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const playbookDef = JSON.parse(readResult.data?.playbook.playbook_definition);
      const entryNodeId = playbookDef.nodes.find((n: any) => n.component_id === PLAYBOOK_INTERNAL_DATA_CRON.id).id;

      const addLinkInput: PlaybookAddLinkInput = {
        from_node: entryNodeId,
        from_port: 'out',
        to_node: secondNodeId,
      };
      await adminQueryWithError(
        {
          query: ADD_LINK_PLAYBOOK,
          variables: {
            id: playbookId,
            input: addLinkInput,
          },
        },
        'Playbook link duplication is not possible',
        UNSUPPORTED_ERROR,
      );
    });
    it('should not add a link with an unknown from_node', async () => {
      const addLinkInput: PlaybookAddLinkInput = {
        from_node: 'fake-node-id',
        from_port: 'out',
        to_node: secondNodeId,
      };
      await adminQueryWithError(
        {
          query: ADD_LINK_PLAYBOOK,
          variables: {
            id: playbookId,
            input: addLinkInput,
          },
        },
        'Playbook link node from not found',
        UNSUPPORTED_ERROR,
      );
    });
    it('should not add a link with an invalid from_port', async () => {
      const readResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const playbookDef = JSON.parse(readResult.data?.playbook.playbook_definition);
      const entryNodeId = playbookDef.nodes.find((n: any) => n.component_id === PLAYBOOK_INTERNAL_DATA_CRON.id).id;

      const addLinkInput: PlaybookAddLinkInput = {
        from_node: entryNodeId,
        from_port: 'fake-port',
        to_node: secondNodeId,
      };
      await adminQueryWithError(
        {
          query: ADD_LINK_PLAYBOOK,
          variables: {
            id: playbookId,
            input: addLinkInput,
          },
        },
        'Playbook link invalid from configuration',
        UNSUPPORTED_ERROR,
      );
    });
    it('should not add a link with an unknown to_node', async () => {
      const readResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const playbookDef = JSON.parse(readResult.data?.playbook.playbook_definition);
      const entryNodeId = playbookDef.nodes.find((n: any) => n.component_id === PLAYBOOK_INTERNAL_DATA_CRON.id).id;

      const addLinkInput: PlaybookAddLinkInput = {
        from_node: entryNodeId,
        from_port: 'out',
        to_node: 'fake-node-id',
      };
      await adminQueryWithError(
        {
          query: ADD_LINK_PLAYBOOK,
          variables: {
            id: playbookId,
            input: addLinkInput,
          },
        },
        'Playbook link node from not found',
        UNSUPPORTED_ERROR,
      );
    });
    it('should not add a link if no Manage Playbooks capability', async () => {
      const readResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const playbookDef = JSON.parse(readResult.data?.playbook.playbook_definition);
      const entryNodeId = playbookDef.nodes.find((n: any) => n.component_id === PLAYBOOK_INTERNAL_DATA_CRON.id).id;

      const addLinkInput: PlaybookAddLinkInput = {
        from_node: entryNodeId,
        from_port: 'out',
        to_node: secondNodeId,
      };
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
        query: ADD_LINK_PLAYBOOK,
        variables: {
          id: playbookId,
          input: addLinkInput,
        },
      });
    });
  });
  describe('playbookDeleteLink', () => {
    it('should not delete a link if no Manage Playbooks capability', async () => {
      const readResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const playbookDef = JSON.parse(readResult.data?.playbook.playbook_definition);
      const linkId = playbookDef.links[0].id;

      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
        query: DELETE_LINK_PLAYBOOK,
        variables: {
          id: playbookId,
          linkId,
        },
      });
    });
    it('should delete an existing link', async () => {
      const readResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const playbookDef = JSON.parse(readResult.data?.playbook.playbook_definition);
      expect(playbookDef.links.length).toEqual(1);
      const linkId = playbookDef.links[0].id;

      const deleteResult = await adminQueryWithSuccess({
        query: DELETE_LINK_PLAYBOOK,
        variables: {
          id: playbookId,
          linkId,
        },
      });
      expect(deleteResult.data?.playbookDeleteLink.id).toBeDefined();

      // Verify link was removed but nodes remain
      const verifyResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const updatedDef = JSON.parse(verifyResult.data?.playbook.playbook_definition);
      expect(updatedDef.links.length).toEqual(0);
      expect(updatedDef.nodes.length).toEqual(2);
    });
    it('should handle deleting a non-existent link gracefully', async () => {
      // Deleting a non-existent linkId just filters it out, no error
      const deleteResult = await adminQueryWithSuccess({
        query: DELETE_LINK_PLAYBOOK,
        variables: {
          id: playbookId,
          linkId: 'non-existent-link-id',
        },
      });
      expect(deleteResult.data?.playbookDeleteLink.id).toBeDefined();
    });
  });
  describe('playbookDeleteNode', () => {
    it('should not delete a node if no Manage Playbooks capability', async () => {
      const readResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const playbookDef = JSON.parse(readResult.data?.playbook.playbook_definition);
      const nodeId = playbookDef.nodes[0].id;

      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
        query: DELETE_NODE_PLAYBOOK,
        variables: {
          id: playbookId,
          nodeId,
        },
      });
    });
    it('should delete a node and its associated links', async () => {
      // Re-add a link between the two existing nodes to test cascading deletion
      const readResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const playbookDef = JSON.parse(readResult.data?.playbook.playbook_definition);
      expect(playbookDef.nodes.length).toEqual(2);
      const entryNodeId = playbookDef.nodes.find((n: any) => n.component_id === PLAYBOOK_INTERNAL_DATA_CRON.id).id;
      const matchingNodeId = playbookDef.nodes.find((n: any) => n.component_id === PLAYBOOK_MATCHING_COMPONENT.id).id;

      // Add a link first
      const addLinkInput: PlaybookAddLinkInput = {
        from_node: entryNodeId,
        from_port: 'out',
        to_node: matchingNodeId,
      };
      await adminQueryWithSuccess({
        query: ADD_LINK_PLAYBOOK,
        variables: {
          id: playbookId,
          input: addLinkInput,
        },
      });

      // Now delete the child node (matching-node) — should also remove the link
      const deleteResult = await adminQueryWithSuccess({
        query: DELETE_NODE_PLAYBOOK,
        variables: {
          id: playbookId,
          nodeId: matchingNodeId,
        },
      });
      expect(deleteResult.data?.playbookDeleteNode.id).toBeDefined();

      // Verify node and link were removed
      const verifyResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const updatedDef = JSON.parse(verifyResult.data?.playbook.playbook_definition);
      expect(updatedDef.nodes.length).toEqual(1);
      expect(updatedDef.nodes[0].id).toEqual(entryNodeId);
      expect(updatedDef.links.length).toEqual(0);
    });
    it('should delete the entry node', async () => {
      const readResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const playbookDef = JSON.parse(readResult.data?.playbook.playbook_definition);
      expect(playbookDef.nodes.length).toEqual(1);
      const entryNodeId = playbookDef.nodes[0].id;

      const deleteResult = await adminQueryWithSuccess({
        query: DELETE_NODE_PLAYBOOK,
        variables: {
          id: playbookId,
          nodeId: entryNodeId,
        },
      });
      expect(deleteResult.data?.playbookDeleteNode.id).toBeDefined();

      // Verify the playbook is now empty
      const verifyResult = await adminQueryWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const updatedDef = JSON.parse(verifyResult.data?.playbook.playbook_definition);
      expect(updatedDef.nodes.length).toEqual(0);
      expect(updatedDef.links.length).toEqual(0);
    });
  });
  it('should not delete playbook if no Manage Playbooks capability', async () => {
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE.client, {
      query: DELETE_PLAYBOOK,
      variables: { id: playbookId },
    });
  });
  it('should remove playbook with Manage Playbooks capability', async () => {
    const queryResult = await queryAsUserWithSuccess(USER_SECURITY.client, {
      query: DELETE_PLAYBOOK,
      variables: { id: playbookId },
    });
    expect(queryResult.data?.playbookDelete).toEqual(playbookId);
  });
});
