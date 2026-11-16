import Workflow from './workflow/Workflow';
import { REQUEST_ACCESS_AUTHOR_KEY, REQUEST_ACCESS_ENTITY_TYPE } from './workflow/utils';
import { ReactFlowProvider } from 'reactflow';
import { ErrorBoundary } from '../../Error';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import useQueryLoading, { useQueryLoadingWithLoadQuery } from '../../../../utils/hooks/useQueryLoading';
import { SubTypeWorkflowQuery, SubTypeWorkflowQuery$data } from './__generated__/SubTypeWorkflowQuery.graphql';
import { SubTypeWorkflowDependenciesQuery } from './__generated__/SubTypeWorkflowDependenciesQuery.graphql';
import Loader from '../../../../components/Loader';
import { Suspense, useCallback, useState } from 'react';

export const workflowQuery = graphql`
  query SubTypeWorkflowQuery($entityType: String!, $allowDraft: Boolean, $scope: StatusScope) {
    workflowDefinition(entityType: $entityType, allowDraft: $allowDraft, scope: $scope) {
      id
      name
      published
      hasPublishedVersion
      errors {
        type
        message
        path {
          id
          entity_type
        }
      }
      initialState
      states {
        statusId
        order
        requestAccessOutcome
        onExit{
          type
          params
        }
        onEnter {
          type
          params
        }
      }
      transitions {
        event
        from
        to
        asyncActions {
          type
          params
        }
        syncActions {
          type
          params
        }
        conditions
        comment
        closingReason
      }
    }
    statusTemplates(search: "") {
      edges {
        node {
          id
          name
          color
        }
      }
    }
  }
`;

export const workflowDependenciesQuery = graphql`
  query SubTypeWorkflowDependenciesQuery($memberFilters: FilterGroup) {
    members(filters: $memberFilters) {
      edges {
        node {
          id
          entity_type
          name
        }
      }
    }
  }
`;

type ActionParams = {
  authorized_members?: { id: string; groups_restriction_ids?: string[] }[];
  actions?: { context?: { values?: string[] } }[];
  organizations?: string[];
};

type ActionList = { type: string; params: unknown }[];

/**
 * Extracts the unique entity IDs referenced by a workflow definition's actions,
 * so that only the relevant members are fetched.
 */
export const extractWorkflowMembersIds = (
  workflowDefinition: SubTypeWorkflowQuery$data['workflowDefinition'],
): string[] => {
  if (!workflowDefinition) return [];

  const allActionLists = [
    ...workflowDefinition.states.flatMap((s) => [s.onEnter, s.onExit]),
    ...workflowDefinition.transitions.flatMap((t) => [t.asyncActions, t.syncActions]),
  ];

  const collected = allActionLists.flatMap((actions) => {
    // Get member IDs from updateAuthorizedMembers actions
    const memberIds = (actions ?? [] as ActionList)
      ?.filter((action) => action.type === 'updateAuthorizedMembers')
      .flatMap((action) => (action.params as ActionParams).authorized_members ?? [])
      .flatMap((authorizedMember) => [authorizedMember.id, ...(authorizedMember.groups_restriction_ids ?? [])]);

    // Get organization IDs from asyncBulkAction actions
    const orgIds = (actions ?? [] as ActionList)
      ?.filter((action) => action.type === 'asyncBulkAction')
      .flatMap((action) => (action.params as ActionParams).actions?.[0]?.context?.values ?? []);

    // Get organization IDs from shareRequestedEntities actions ('AUTHOR' is a dynamic key, not an entity)
    const requestedEntitiesOrgIds = (actions ?? [] as ActionList)
      ?.filter((action) => action.type === 'shareRequestedEntities')
      .flatMap((action) => (action.params as ActionParams).organizations ?? [])
      .filter((id) => id !== REQUEST_ACCESS_AUTHOR_KEY);

    return [...memberIds, ...orgIds, ...requestedEntitiesOrgIds];
  });

  // Remove duplicates and falsy values
  return Array.from(new Set(collected)).filter(Boolean) as string[];
};

export type WorkflowScope = NonNullable<SubTypeWorkflowQuery['variables']['scope']>;

interface WorkflowWithDependenciesProps {
  queryRef: PreloadedQuery<SubTypeWorkflowQuery>;
  onRefetch: () => void;
  entityType: string;
  scope: WorkflowScope;
  onScopeChange: (scope: WorkflowScope) => void;
}

const WorkflowWithDependencies = ({ queryRef, onRefetch, entityType, scope, onScopeChange }: WorkflowWithDependenciesProps) => {
  const { workflowDefinition } = usePreloadedQuery<SubTypeWorkflowQuery>(workflowQuery, queryRef);
  const memberIds = extractWorkflowMembersIds(workflowDefinition);

  const depsQueryRef = useQueryLoading<SubTypeWorkflowDependenciesQuery>(workflowDependenciesQuery,
    {
      memberFilters: memberIds.length
        ? ({ mode: 'and' as const, filters: [{ key: ['id'], values: memberIds }], filterGroups: [] })
        : null,
    },
  );

  if (!depsQueryRef) return <Loader />;

  return (
    <Suspense fallback={<Loader />}>
      <Workflow
        queryRef={queryRef}
        depsQueryRef={depsQueryRef}
        onRefetch={onRefetch}
        entityType={entityType}
        scope={scope}
        onScopeChange={onScopeChange}
      />
    </Suspense>
  );
};

interface ScopedSubTypeWorkflowProps {
  entityType: string;
  scope: WorkflowScope;
  onScopeChange: (scope: WorkflowScope) => void;
}

const ScopedSubTypeWorkflow = ({ entityType, scope, onScopeChange }: ScopedSubTypeWorkflowProps) => {
  const [workflowQueryRef, loadWorkflowQuery] = useQueryLoadingWithLoadQuery<SubTypeWorkflowQuery>(
    workflowQuery,
    { entityType, allowDraft: true, scope },
    { fetchPolicy: 'network-only' },
  );

  const handleRefetch = useCallback(() => {
    loadWorkflowQuery({ entityType, allowDraft: true, scope }, { fetchPolicy: 'network-only' });
  }, [loadWorkflowQuery, entityType, scope]);

  if (!workflowQueryRef) {
    return <Loader />;
  }

  return (
    <Suspense fallback={<Loader />}>
      <ErrorBoundary>
        <div style={{ width: '100%', height: 'calc(100vh - 250px)', marginBottom: '-50px' }}>
          <ReactFlowProvider>
            <WorkflowWithDependencies
              queryRef={workflowQueryRef}
              onRefetch={handleRefetch}
              entityType={entityType}
              scope={scope}
              onScopeChange={onScopeChange}
            />
          </ReactFlowProvider>
        </div>
      </ErrorBoundary>
    </Suspense>
  );
};

interface SubTypeWorkflowProps {
  entityType?: string;
}

const SubTypeWorkflowForType = ({ entityType }: { entityType: string }) => {
  const [requestedScope, setRequestedScope] = useState<WorkflowScope>('GLOBAL');
  // The scope chosen on Case-Rfi must not follow the user to another entity type.
  const scope = entityType === REQUEST_ACCESS_ENTITY_TYPE ? requestedScope : 'GLOBAL';

  // Keyed by scope: each scope edits its own definition, so nothing of the other one
  // (graph, publish status, pending autosave) may leak across the switch.
  return <ScopedSubTypeWorkflow key={scope} entityType={entityType} scope={scope} onScopeChange={setRequestedScope} />;
};

const SubTypeWorkflow = ({ entityType = 'DraftWorkspace' }: SubTypeWorkflowProps) => {
  // Keyed by entity type: coming back to Case-Rfi reopens it on the Global scope.
  return <SubTypeWorkflowForType key={entityType} entityType={entityType} />;
};

export default SubTypeWorkflow;
