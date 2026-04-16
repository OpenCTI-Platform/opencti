import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithError, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import type { PlaybookAddLinkInput, PlaybookAddNodeInput } from '../../../src/generated/graphql';
import { PLAYBOOK_INTERNAL_DATA_CRON, PLAYBOOK_MATCHING_COMPONENT } from '../../../src/modules/playbook/playbook-components';
import { UNSUPPORTED_ERROR } from '../../../src/config/errors';
import { getUserIdByEmail, USER_PARTICIPATE, USER_SECURITY } from '../../utils/testQuery';

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
      created_at
      updated_at
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
      created_at
      updated_at
      creators {
        id
        name
      }
    }
  }
`;

const UPDATE_PLAYBOOK = gql`
  mutation playbookFieldPatchEdit($id: ID!, $input: [EditInput!]!) {
    playbookFieldPatch(id: $id, input: $input) {
      id
      name
      updated_at
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

const EMPTY_STRING_FILTERS = JSON.stringify({
  mode: 'and',
  filters: [
    { key: ['entity_type'], values: ['Report'], operator: 'eq' },
  ],
  filterGroups: [],
});

// -- Helpers to build playbook state --

const createPlaybook = async (name: string) => {
  const result = await queryAsUserWithSuccess(USER_SECURITY, {
    query: CREATE_PLAYBOOK,
    variables: { input: { name } },
  });
  return result.data?.playbookAdd;
};

const deletePlaybook = async (id: string) => {
  await queryAsUserWithSuccess(USER_SECURITY, {
    query: DELETE_PLAYBOOK,
    variables: { id },
  });
};

const addEntryNode = async (playbookId: string, name = 'entry-node'): Promise<string> => {
  const addNodeInput: PlaybookAddNodeInput = {
    component_id: PLAYBOOK_INTERNAL_DATA_CRON.id,
    configuration: JSON.stringify({ filters: EMPTY_STRING_FILTERS }),
    name,
    position: { x: 1, y: 1 },
  };
  const result = await queryAsAdminWithSuccess({
    query: ADD_NODE_PLAYBOOK,
    variables: { id: playbookId, input: addNodeInput },
  });
  return result.data?.playbookAddNode;
};

const addMatchingNode = async (playbookId: string, name = 'matching-node'): Promise<string> => {
  const addNodeInput: PlaybookAddNodeInput = {
    component_id: PLAYBOOK_MATCHING_COMPONENT.id,
    configuration: JSON.stringify({ filters: EMPTY_STRING_FILTERS }),
    name,
    position: { x: 5, y: 5 },
  };
  const result = await queryAsAdminWithSuccess({
    query: ADD_NODE_PLAYBOOK,
    variables: { id: playbookId, input: addNodeInput },
  });
  return result.data?.playbookAddNode;
};

const addLink = async (playbookId: string, fromNode: string, toNode: string, fromPort = 'out'): Promise<string> => {
  const addLinkInput: PlaybookAddLinkInput = {
    from_node: fromNode,
    from_port: fromPort,
    to_node: toNode,
  };
  const result = await queryAsAdminWithSuccess({
    query: ADD_LINK_PLAYBOOK,
    variables: { id: playbookId, input: addLinkInput },
  });
  return result.data?.playbookAddLink;
};

const readPlaybookDefinition = async (playbookId: string) => {
  const result = await queryAsAdminWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
  return JSON.parse(result.data?.playbook.playbook_definition);
};

const clearPlaybook = async (playbookId: string) => {
  const playbookDef = await readPlaybookDefinition(playbookId);
  // Delete all links first
  for (const link of playbookDef.links) {
    await queryAsAdminWithSuccess({
      query: DELETE_LINK_PLAYBOOK,
      variables: { id: playbookId, linkId: link.id },
    });
  }
  // Then delete all nodes
  for (const node of playbookDef.nodes) {
    await queryAsAdminWithSuccess({
      query: DELETE_NODE_PLAYBOOK,
      variables: { id: playbookId, nodeId: node.id },
    });
  }
};

describe('Playbook resolver standard behavior', () => {
  let playbookId = '';
  let playbookCreatedAt = '';
  let playbookUpdatedAt = '';
  let entryNodeId = '';
  let matchingNodeId = '';
  let linkId = '';

  beforeAll(async () => {
    const playbook = await createPlaybook('Playbook1');
    playbookId = playbook.id;
    playbookCreatedAt = playbook.created_at;
    playbookUpdatedAt = playbook.updated_at;
  });

  afterAll(async () => {
    // May already be deleted by the playbookDelete describe
    await deletePlaybook(playbookId).catch(() => {});
  });

  describe('playbook CRUD', () => {
    it('should have created_at and updated_at set on creation', () => {
      expect(playbookCreatedAt).toBeDefined();
      expect(playbookUpdatedAt).toBeDefined();
      // Both timestamps should be valid ISO date strings
      expect(new Date(playbookCreatedAt).getTime()).not.toBeNaN();
      expect(new Date(playbookUpdatedAt).getTime()).not.toBeNaN();
    });

    it('should list playbooks', async () => {
      const queryResult = await queryAsAdminWithSuccess({ query: LIST_PLAYBOOKS, variables: { first: 10 } });
      expect(queryResult.data?.playbooks.edges.length).toEqual(1);
    });

    it('should not add playbook if no Manage Playbooks capability', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
        query: CREATE_PLAYBOOK,
        variables: { input: { name: 'Playbook-forbidden' } },
      });
    });

    it('should read playbook', async () => {
      const queryResult = await queryAsAdminWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const playbook = queryResult.data?.playbook;
      expect(playbook?.name).toEqual('Playbook1');
      expect(playbook?.playbook_running).toEqual(false);
      // created_at and updated_at should be returned and should match the original values
      expect(playbook?.created_at).toBeDefined();
      expect(playbook?.updated_at).toBeDefined();
      expect(playbook?.created_at).toEqual(playbookCreatedAt);
      // creators should be returned and contain the user who created the playbook
      expect(playbook?.creators.length).toEqual(1);
      const securityUserId = await getUserIdByEmail(USER_SECURITY.email);
      expect(playbook?.creators[0].id).toEqual(securityUserId);
    });

    it('should not update playbook if no Manage Playbooks capability', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
        query: UPDATE_PLAYBOOK,
        variables: {
          id: playbookId,
          input: [{ key: 'name', value: ['Playbook1 - updated'] }],
        },
      });
    });

    it('should update playbook with Manage Playbooks capability', async () => {
      const queryResult = await queryAsUserWithSuccess(USER_SECURITY, {
        query: UPDATE_PLAYBOOK,
        variables: {
          id: playbookId,
          input: [{ key: 'name', value: ['Playbook1 - updated'] }],
        },
      });
      expect(queryResult.data?.playbookFieldPatch.name).toEqual('Playbook1 - updated');
    });

    it('should have updated_at changed after update', async () => {
      const queryResult = await queryAsAdminWithSuccess({ query: READ_PLAYBOOK, variables: { id: playbookId } });
      const newUpdatedAt = queryResult.data?.playbook.updated_at;
      expect(newUpdatedAt).toBeDefined();
      // updated_at should be > the original value after an update
      expect(new Date(newUpdatedAt).getTime()).toBeGreaterThan(new Date(playbookUpdatedAt).getTime());
      // created_at should remain unchanged
      expect(queryResult.data?.playbook.created_at).toEqual(playbookCreatedAt);
    });
  });

  describe('playbookAddNode', () => {
    // playbook is empty after global creation

    it('should add entry node to a playbook', async () => {
      const addNodeInput: PlaybookAddNodeInput = {
        component_id: PLAYBOOK_INTERNAL_DATA_CRON.id,
        configuration: JSON.stringify({ filters: EMPTY_STRING_FILTERS }),
        name: 'node1',
        position: { x: 1, y: 1 },
      };
      await queryAsAdminWithSuccess({
        query: ADD_NODE_PLAYBOOK,
        variables: { id: playbookId, input: addNodeInput },
      });
      const playbookDef = await readPlaybookDefinition(playbookId);
      expect(playbookDef.nodes.length).toEqual(1);
      const node1 = playbookDef.nodes[0];
      expect(node1.name).toEqual('node1');
      expect(node1.position.x).toEqual(1);
      expect(JSON.parse(node1.configuration).filters).toEqual(EMPTY_STRING_FILTERS);
    });

    it('should not add several entry nodes to a playbook', async () => {
      // Ensure an entry node exists
      const playbookDef = await readPlaybookDefinition(playbookId);
      if (playbookDef.nodes.length === 0) {
        await addEntryNode(playbookId);
      }
      const addNodeInput: PlaybookAddNodeInput = {
        component_id: PLAYBOOK_INTERNAL_DATA_CRON.id,
        configuration: JSON.stringify({ filters: EMPTY_STRING_FILTERS }),
        name: 'duplicate-entry',
        position: { x: 1, y: 2 },
      };
      await queryAsAdminWithError(
        {
          query: ADD_NODE_PLAYBOOK,
          variables: { id: playbookId, input: addNodeInput },
        },
        'Playbook multiple entrypoint is not supported',
        UNSUPPORTED_ERROR,
      );
    });

    it('should not add unknown component to a playbook', async () => {
      const addNodeInput: PlaybookAddNodeInput = {
        component_id: 'fake_component_id',
        configuration: JSON.stringify({ filters: EMPTY_STRING_FILTERS }),
        name: 'unknown-component',
        position: { x: 3, y: 12 },
      };
      await queryAsAdminWithError(
        {
          query: ADD_NODE_PLAYBOOK,
          variables: { id: playbookId, input: addNodeInput },
        },
        'Playbook related component not found',
        UNSUPPORTED_ERROR,
      );
    });

    it('should not add node with incorrect filters for PLAYBOOK_INTERNAL_DATA_CRON component', async () => {
      const incorrectStringFilters = JSON.stringify({
        mode: 'and',
        filters: [{ key: ['fake_key'], values: [], operator: 'nil' }],
        filterGroups: [],
      });
      const addNodeInput: PlaybookAddNodeInput = {
        component_id: PLAYBOOK_INTERNAL_DATA_CRON.id,
        configuration: JSON.stringify({ filters: incorrectStringFilters }),
        name: 'incorrectNode',
        position: { x: 1, y: 1 },
      };
      await queryAsAdminWithError(
        {
          query: ADD_NODE_PLAYBOOK,
          variables: { id: playbookId, input: addNodeInput },
        },
        'Incorrect filter keys not existing in any schema definition',
        UNSUPPORTED_ERROR,
      );
    });

    it('should not add node with incorrect filters for components with stix filtering', async () => {
      const incorrectStringFilters = JSON.stringify({
        mode: 'and',
        filters: [{ key: ['published'], values: [], operator: 'nil' }],
        filterGroups: [],
      });
      const addNodeInput: PlaybookAddNodeInput = {
        component_id: PLAYBOOK_MATCHING_COMPONENT.id,
        configuration: JSON.stringify({ filters: incorrectStringFilters }),
        name: 'incorrectNode',
        position: { x: 1, y: 1 },
      };
      await queryAsAdminWithError(
        {
          query: ADD_NODE_PLAYBOOK,
          variables: { id: playbookId, input: addNodeInput },
        },
        'Stix filtering is not compatible with the provided filter key',
        UNSUPPORTED_ERROR,
      );
    });
  });

  describe('playbookReplaceNode', () => {
    beforeAll(async () => {
      await clearPlaybook(playbookId);
      entryNodeId = await addEntryNode(playbookId, 'node-to-replace');
    });

    it('should replace an existing node in the playbook', async () => {
      const replaceNodeInput: PlaybookAddNodeInput = {
        component_id: PLAYBOOK_INTERNAL_DATA_CRON.id,
        configuration: JSON.stringify({ filters: EMPTY_STRING_FILTERS }),
        name: 'node1-replaced',
        position: { x: 10, y: 20 },
      };
      const replaceResult = await queryAsAdminWithSuccess({
        query: REPLACE_NODE_PLAYBOOK,
        variables: { id: playbookId, nodeId: entryNodeId, input: replaceNodeInput },
      });
      expect(replaceResult.data?.playbookReplaceNode).toEqual(entryNodeId);

      const playbookDef = await readPlaybookDefinition(playbookId);
      expect(playbookDef.nodes.length).toEqual(1);
      const replacedNode = playbookDef.nodes[0];
      expect(replacedNode.id).toEqual(entryNodeId);
      expect(replacedNode.name).toEqual('node1-replaced');
      expect(replacedNode.position.x).toEqual(10);
      expect(replacedNode.position.y).toEqual(20);
      expect(replacedNode.component_id).toEqual(PLAYBOOK_INTERNAL_DATA_CRON.id);
    });

    it('should not replace a node with an unknown component', async () => {
      const replaceNodeInput: PlaybookAddNodeInput = {
        component_id: 'fake_component_id',
        configuration: JSON.stringify({ filters: EMPTY_STRING_FILTERS }),
        name: 'bad-node',
        position: { x: 1, y: 1 },
      };
      await queryAsAdminWithError(
        {
          query: REPLACE_NODE_PLAYBOOK,
          variables: { id: playbookId, nodeId: entryNodeId, input: replaceNodeInput },
        },
        'Playbook related component not found',
        UNSUPPORTED_ERROR,
      );
    });

    it('should not replace a node with incorrect filters', async () => {
      const incorrectStringFilters = JSON.stringify({
        mode: 'and',
        filters: [{ key: ['fake_key'], values: [], operator: 'nil' }],
        filterGroups: [],
      });
      const replaceNodeInput: PlaybookAddNodeInput = {
        component_id: PLAYBOOK_INTERNAL_DATA_CRON.id,
        configuration: JSON.stringify({ filters: incorrectStringFilters }),
        name: 'bad-filters-node',
        position: { x: 1, y: 1 },
      };
      await queryAsAdminWithError(
        {
          query: REPLACE_NODE_PLAYBOOK,
          variables: { id: playbookId, nodeId: entryNodeId, input: replaceNodeInput },
        },
        'Incorrect filter keys not existing in any schema definition',
        UNSUPPORTED_ERROR,
      );
    });

    it('should not replace a node if no Manage Playbooks capability', async () => {
      const replaceNodeInput: PlaybookAddNodeInput = {
        component_id: PLAYBOOK_INTERNAL_DATA_CRON.id,
        configuration: JSON.stringify({ filters: EMPTY_STRING_FILTERS }),
        name: 'forbidden-replace',
        position: { x: 1, y: 1 },
      };
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
        query: REPLACE_NODE_PLAYBOOK,
        variables: { id: playbookId, nodeId: entryNodeId, input: replaceNodeInput },
      });
    });
  });

  describe('playbookAddLink', () => {
    beforeAll(async () => {
      await clearPlaybook(playbookId);
      entryNodeId = await addEntryNode(playbookId);
      matchingNodeId = await addMatchingNode(playbookId);
    });

    it('should add a link between two nodes', async () => {
      linkId = await addLink(playbookId, entryNodeId, matchingNodeId);
      expect(linkId).toBeDefined();

      const playbookDef = await readPlaybookDefinition(playbookId);
      expect(playbookDef.links.length).toEqual(1);
      const link = playbookDef.links[0];
      expect(link.id).toEqual(linkId);
      expect(link.from.id).toEqual(entryNodeId);
      expect(link.from.port).toEqual('out');
      expect(link.to.id).toEqual(matchingNodeId);
    });

    it('should not add a duplicate link', async () => {
      // Ensure a link exists first
      const playbookDef = await readPlaybookDefinition(playbookId);
      if (playbookDef.links.length === 0) {
        await addLink(playbookId, entryNodeId, matchingNodeId);
      }
      const addLinkInput: PlaybookAddLinkInput = {
        from_node: entryNodeId,
        from_port: 'out',
        to_node: matchingNodeId,
      };
      await queryAsAdminWithError(
        {
          query: ADD_LINK_PLAYBOOK,
          variables: { id: playbookId, input: addLinkInput },
        },
        'Playbook link duplication is not possible',
        UNSUPPORTED_ERROR,
      );
    });

    it('should not add a link with an unknown from_node', async () => {
      const addLinkInput: PlaybookAddLinkInput = {
        from_node: 'fake-node-id',
        from_port: 'out',
        to_node: matchingNodeId,
      };
      await queryAsAdminWithError(
        {
          query: ADD_LINK_PLAYBOOK,
          variables: { id: playbookId, input: addLinkInput },
        },
        'Playbook link node from not found',
        UNSUPPORTED_ERROR,
      );
    });

    it('should not add a link with an invalid from_port', async () => {
      const addLinkInput: PlaybookAddLinkInput = {
        from_node: entryNodeId,
        from_port: 'fake-port',
        to_node: matchingNodeId,
      };
      await queryAsAdminWithError(
        {
          query: ADD_LINK_PLAYBOOK,
          variables: { id: playbookId, input: addLinkInput },
        },
        'Playbook link invalid from configuration',
        UNSUPPORTED_ERROR,
      );
    });

    it('should not add a link with an unknown to_node', async () => {
      const addLinkInput: PlaybookAddLinkInput = {
        from_node: entryNodeId,
        from_port: 'out',
        to_node: 'fake-node-id',
      };
      await queryAsAdminWithError(
        {
          query: ADD_LINK_PLAYBOOK,
          variables: { id: playbookId, input: addLinkInput },
        },
        'Playbook link node from not found',
        UNSUPPORTED_ERROR,
      );
    });

    it('should not add a link if no Manage Playbooks capability', async () => {
      const addLinkInput: PlaybookAddLinkInput = {
        from_node: entryNodeId,
        from_port: 'out',
        to_node: matchingNodeId,
      };
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
        query: ADD_LINK_PLAYBOOK,
        variables: { id: playbookId, input: addLinkInput },
      });
    });
  });

  describe('playbookDeleteLink', () => {
    beforeAll(async () => {
      await clearPlaybook(playbookId);
      entryNodeId = await addEntryNode(playbookId);
      matchingNodeId = await addMatchingNode(playbookId);
      linkId = await addLink(playbookId, entryNodeId, matchingNodeId);
    });

    it('should not delete a link if no Manage Playbooks capability', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
        query: DELETE_LINK_PLAYBOOK,
        variables: { id: playbookId, linkId },
      });
    });

    it('should delete an existing link and keep nodes', async () => {
      const deleteResult = await queryAsAdminWithSuccess({
        query: DELETE_LINK_PLAYBOOK,
        variables: { id: playbookId, linkId },
      });
      expect(deleteResult.data?.playbookDeleteLink.id).toBeDefined();

      const playbookDef = await readPlaybookDefinition(playbookId);
      expect(playbookDef.links.length).toEqual(0);
      expect(playbookDef.nodes.length).toEqual(2);
    });

    it('should handle deleting a non-existent link gracefully', async () => {
      const deleteResult = await queryAsAdminWithSuccess({
        query: DELETE_LINK_PLAYBOOK,
        variables: { id: playbookId, linkId: 'non-existent-link-id' },
      });
      expect(deleteResult.data?.playbookDeleteLink.id).toBeDefined();
    });
  });

  describe('playbookDeleteNode', () => {
    beforeAll(async () => {
      await clearPlaybook(playbookId);
      entryNodeId = await addEntryNode(playbookId);
      matchingNodeId = await addMatchingNode(playbookId);
      await addLink(playbookId, entryNodeId, matchingNodeId);
    });

    it('should not delete a node if no Manage Playbooks capability', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
        query: DELETE_NODE_PLAYBOOK,
        variables: { id: playbookId, nodeId: entryNodeId },
      });
    });

    it('should delete a node and its associated links', async () => {
      const deleteResult = await queryAsAdminWithSuccess({
        query: DELETE_NODE_PLAYBOOK,
        variables: { id: playbookId, nodeId: matchingNodeId },
      });
      expect(deleteResult.data?.playbookDeleteNode.id).toBeDefined();

      const playbookDef = await readPlaybookDefinition(playbookId);
      expect(playbookDef.nodes.length).toEqual(1);
      expect(playbookDef.nodes[0].id).toEqual(entryNodeId);
      expect(playbookDef.links.length).toEqual(0);
    });

    it('should delete the last remaining entry node and leave the playbook empty', async () => {
      const deleteResult = await queryAsAdminWithSuccess({
        query: DELETE_NODE_PLAYBOOK,
        variables: { id: playbookId, nodeId: entryNodeId },
      });
      expect(deleteResult.data?.playbookDeleteNode.id).toBeDefined();

      const playbookDef = await readPlaybookDefinition(playbookId);
      expect(playbookDef.nodes.length).toEqual(0);
      expect(playbookDef.links.length).toEqual(0);
    });
  });

  describe('playbookDelete', () => {
    it('should not delete playbook if no Manage Playbooks capability', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
        query: DELETE_PLAYBOOK,
        variables: { id: playbookId },
      });
    });

    it('should remove playbook with Manage Playbooks capability', async () => {
      const queryResult = await queryAsUserWithSuccess(USER_SECURITY, {
        query: DELETE_PLAYBOOK,
        variables: { id: playbookId },
      });
      expect(queryResult.data?.playbookDelete).toEqual(playbookId);
    });
  });
});
