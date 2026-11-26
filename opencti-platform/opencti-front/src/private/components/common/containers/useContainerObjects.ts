import { RecordSourceSelectorProxy } from 'relay-runtime';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { deleteNodeFromId, insertNode } from '../../../../utils/store';
// The generated requests are imported directly: importing them from ContainerAddStixCoreObjectsLines would create an import cycle
import relationAddMutation, { ContainerAddStixCoreObjectsLinesRelationAddMutation } from './__generated__/ContainerAddStixCoreObjectsLinesRelationAddMutation.graphql';
import relationDeleteMutation, { ContainerAddStixCoreObjectsLinesRelationDeleteMutation } from './__generated__/ContainerAddStixCoreObjectsLinesRelationDeleteMutation.graphql';
import knowledgeGraphRelationAddMutation, {
  ReportKnowledgeGraphQueryRelationAddMutation,
} from '../../analyses/reports/__generated__/ReportKnowledgeGraphQueryRelationAddMutation.graphql';
import knowledgeGraphRelationDeleteMutation, {
  ReportKnowledgeGraphQueryRelationDeleteMutation,
} from '../../analyses/reports/__generated__/ReportKnowledgeGraphQueryRelationDeleteMutation.graphql';

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

/**
 * Adds objects to a container (`object` ref) and removes them, like ticking and unticking them in the container's add panel.
 * The returned promises settle once the mutation is done: a failure is shown by useApiMutation, then rejects.
 */
export const useContainerObjects = () => {
  const [commitAdd] = useApiMutation<ContainerAddStixCoreObjectsLinesRelationAddMutation>(relationAddMutation);
  const [commitDelete] = useApiMutation<ContainerAddStixCoreObjectsLinesRelationDeleteMutation>(relationDeleteMutation);
  const [commitKnowledgeGraphAdd] = useApiMutation<ReportKnowledgeGraphQueryRelationAddMutation>(knowledgeGraphRelationAddMutation);
  const [commitKnowledgeGraphDelete] = useApiMutation<ReportKnowledgeGraphQueryRelationDeleteMutation>(knowledgeGraphRelationDeleteMutation);

  const addObjectToContainer = ({
    containerId,
    objectId,
    knowledgeGraph,
    paginationOptions,
    commitMessage = '',
    references = [],
    optimisticUpdater,
  }: ContainerObjectMutationArgs) => new Promise<void>((resolve, reject) => {
    const input = { toId: objectId, relationship_type: 'object' };
    const variables = { id: containerId, input, commitMessage, references };
    const callbacks = { onCompleted: () => resolve(), onError: (error: Error) => reject(error) };
    if (knowledgeGraph) {
      commitKnowledgeGraphAdd({ variables, optimisticUpdater, ...callbacks });
      return;
    }
    commitAdd({
      variables,
      optimisticUpdater,
      updater: (store: RecordSourceSelectorProxy) => {
        insertNode(
          store,
          'Pagination_objects',
          paginationOptions,
          'containerEdit',
          containerId,
          'relationAdd',
          { input, commitMessage, references },
          'to',
        );
      },
      ...callbacks,
    });
  });

  /** The object itself is not deleted. */
  const removeObjectFromContainer = ({
    containerId,
    objectId,
    knowledgeGraph,
    paginationOptions,
    commitMessage = '',
    references = [],
  }: ContainerObjectMutationArgs) => new Promise<void>((resolve, reject) => {
    const variables = { id: containerId, toId: objectId, relationship_type: 'object', commitMessage, references };
    const callbacks = { onCompleted: () => resolve(), onError: (error: Error) => reject(error) };
    if (knowledgeGraph) {
      commitKnowledgeGraphDelete({ variables, ...callbacks });
      return;
    }
    commitDelete({
      variables,
      updater: (store: RecordSourceSelectorProxy) => {
        deleteNodeFromId(store, containerId, 'Pagination_objects', paginationOptions, objectId);
      },
      ...callbacks,
    });
  });

  return { addObjectToContainer, removeObjectFromContainer };
};
