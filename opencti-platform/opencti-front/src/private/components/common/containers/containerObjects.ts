import { ConnectionHandler, RecordSourceSelectorProxy } from 'relay-runtime';
import { commitMutation } from '../../../../relay/environment';
import { insertNode } from '../../../../utils/store';
// The generated requests are imported directly: importing them from ContainerAddStixCoreObjectsLines would create an import cycle
import relationAddMutation from './__generated__/ContainerAddStixCoreObjectsLinesRelationAddMutation.graphql';
import relationDeleteMutation from './__generated__/ContainerAddStixCoreObjectsLinesRelationDeleteMutation.graphql';
import knowledgeGraphRelationAddMutation from '../../analyses/reports/__generated__/ReportKnowledgeGraphQueryRelationAddMutation.graphql';
import knowledgeGraphRelationDeleteMutation from '../../analyses/reports/__generated__/ReportKnowledgeGraphQueryRelationDeleteMutation.graphql';

/** An object just created by a creation form, as returned by its creation mutation. */
export interface CreatedObject {
  id: string;
  standard_id?: string;
  entity_type: string;
  parent_types?: readonly string[];
  representative?: { main: string } | null;
}

export interface ContainerObjectMutationArgs {
  containerId: string;
  objectId: string;
  // The knowledge graph keeps its own data, so the container's object list is not updated in the store
  knowledgeGraph?: boolean;
  // Pagination options of the container's object list (`Pagination_objects`) to update in the store
  paginationOptions?: Record<string, unknown>;
  commitMessage?: string;
  references?: string[];
  optimisticUpdater?: () => void;
}

// ID and count are not valid connection filters
const connectionFilters = (paginationOptions?: Record<string, unknown>) => {
  const { id: _, count: __, ...filters } = paginationOptions ?? {};
  return filters;
};

/** Adds an object to a container (`object` ref), like ticking it in the container's add panel. */
export const addObjectToContainer = ({
  containerId,
  objectId,
  knowledgeGraph,
  paginationOptions,
  commitMessage = '',
  references = [],
  optimisticUpdater,
}: ContainerObjectMutationArgs) => new Promise<void>((resolve, reject) => {
  const input = { toId: objectId, relationship_type: 'object' };
  commitMutation({
    mutation: knowledgeGraph ? knowledgeGraphRelationAddMutation : relationAddMutation,
    variables: { id: containerId, input, commitMessage, references },
    optimisticUpdater,
    updater: knowledgeGraph ? undefined : (store: RecordSourceSelectorProxy) => {
      insertNode(
        store,
        'Pagination_objects',
        connectionFilters(paginationOptions),
        'containerEdit',
        containerId,
        'relationAdd',
        { input, commitMessage, references },
        'to',
      );
    },
    onCompleted: () => resolve(),
    onError: (error: Error) => reject(error),
  });
});

/** Removes an object from a container: the object itself is not deleted. */
export const removeObjectFromContainer = ({
  containerId,
  objectId,
  knowledgeGraph,
  paginationOptions,
  commitMessage = '',
  references = [],
}: ContainerObjectMutationArgs) => new Promise<void>((resolve, reject) => {
  commitMutation({
    mutation: knowledgeGraph ? knowledgeGraphRelationDeleteMutation : relationDeleteMutation,
    variables: { id: containerId, toId: objectId, relationship_type: 'object', commitMessage, references },
    updater: knowledgeGraph ? undefined : (store: RecordSourceSelectorProxy) => {
      const containerRecord = store.get(containerId);
      const conn = containerRecord && ConnectionHandler.getConnection(
        containerRecord,
        'Pagination_objects',
        connectionFilters(paginationOptions),
      );
      if (conn) ConnectionHandler.deleteNode(conn, objectId);
    },
    onCompleted: () => resolve(),
    onError: (error: Error) => reject(error),
  });
});
