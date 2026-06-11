import Workflow from './workflow/Workflow';
import { ReactFlowProvider } from 'reactflow';
import { ErrorBoundary } from '../../Error';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { SubTypeWorkflowQuery, SubTypeWorkflowQuery$data } from './__generated__/SubTypeWorkflowQuery.graphql';
import { SubTypeWorkflowDependenciesQuery } from './__generated__/SubTypeWorkflowDependenciesQuery.graphql';
import Loader from '../../../../components/Loader';
import { Suspense } from 'react';

export const workflowQuery = graphql`
  query SubTypeWorkflowQuery($entityType: String!, $allowDraft: Boolean) {
    workflowDefinition(entityType: $entityType, allowDraft: $allowDraft) {
      id
      name
      published
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
  query SubTypeWorkflowDependenciesQuery(
    $memberFilters: FilterGroup
    $memberFirst: Int
  ) {
    members(filters: $memberFilters, first: $memberFirst) {
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

    return [...memberIds, ...orgIds];
  });

  // Remove duplicates and falsy values
  return Array.from(new Set(collected)).filter(Boolean) as string[];
};

interface WorkflowWithDependenciesProps {
  queryRef: PreloadedQuery<SubTypeWorkflowQuery>;
}

const WorkflowWithDependencies = ({ queryRef }: WorkflowWithDependenciesProps) => {
  const { workflowDefinition } = usePreloadedQuery<SubTypeWorkflowQuery>(workflowQuery, queryRef);
  const memberIds = extractWorkflowMembersIds(workflowDefinition);

  const depsQueryRef = useQueryLoading<SubTypeWorkflowDependenciesQuery>(workflowDependenciesQuery,
    {
      memberFilters: memberIds.length
        ? ({
            mode: 'and' as const,
            filters: [{ key: ['id'], values: memberIds }],
            filterGroups: [],
          })
        : null,
    },
  );

  if (!depsQueryRef) return <Loader />;

  return (
    <Suspense fallback={<Loader />}>
      <Workflow queryRef={queryRef} depsQueryRef={depsQueryRef} />
    </Suspense>
  );
};

const SubTypeWorkflow = () => {
  const workflowQueryRef = useQueryLoading<SubTypeWorkflowQuery>(
    workflowQuery,
    { entityType: 'DraftWorkspace', allowDraft: true },
  );

  if (!workflowQueryRef) {
    return <Loader />;
  }

  return (
    <Suspense fallback={<Loader />}>
      <ErrorBoundary>
        <div style={{ width: '100%', height: 'calc(100vh - 250px)', marginBottom: '-50px' }}>
          <ReactFlowProvider>
            <WorkflowWithDependencies queryRef={workflowQueryRef} />
          </ReactFlowProvider>
        </div>
      </ErrorBoundary>
    </Suspense>
  );
};

export default SubTypeWorkflow;
