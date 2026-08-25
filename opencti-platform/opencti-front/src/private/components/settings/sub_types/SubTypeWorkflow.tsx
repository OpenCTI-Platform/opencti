import { Suspense, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useOutletContext } from 'react-router-dom';
import { ReactFlowProvider } from 'reactflow';
import Loader from '../../../../components/Loader';
import { UserContext } from '../../../../utils/hooks/useAuth';
import useQueryLoading, { useQueryLoadingWithLoadQuery } from '../../../../utils/hooks/useQueryLoading';
import { StatusScopeEnum } from '../../../../utils/statusConstants';
import { hasRequestAccessWorkflowConfig } from '../../common/workflow/hasRequestAccessWorkflowConfig';
import { ErrorBoundary } from '../../Error';
import { SubTypeWorkflowDependenciesQuery } from './__generated__/SubTypeWorkflowDependenciesQuery.graphql';
import { SubTypeWorkflowQuery, SubTypeWorkflowQuery$data } from './__generated__/SubTypeWorkflowQuery.graphql';
import { SubTypeOutletContext } from './SubTypeOutletContext';
import Workflow from './workflow/Workflow';
import WorkflowMigrationConfirmDialog from './workflow/WorkflowMigrationConfirmDialog';

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
  onRefetch: () => void;
  entityType: string;
  canSwitchScope: boolean;
  scope: StatusScopeEnum;
  onScopeChange: (scope: StatusScopeEnum) => void;
}

const WorkflowWithDependencies = ({ queryRef, onRefetch, entityType, canSwitchScope, scope, onScopeChange }: WorkflowWithDependenciesProps) => {
  const { workflowDefinition } = usePreloadedQuery<SubTypeWorkflowQuery>(workflowQuery, queryRef);
  const memberIds = extractWorkflowMembersIds(workflowDefinition);

  // Gates entry to the graph editor while `workflowDefinition` is null (no workflow authored yet
  // for this entityType/scope) and legacy `Status` data exists to migrate. Reset whenever the
  // entityType/scope actually changes (not on initial mount, where the `useState(false)` default
  // is already correct) so a rescoped view gets its own gate. Skipping the initial invocation
  // matters: effects run children-first, so on mount the migration dialog's `onNoLegacyData`
  // effect (which clears the gate) fires before this one — if this effect unconditionally reset
  // the gate on mount too, it would silently overwrite that update back to `false` and get the
  // component stuck showing nothing.
  const [migrationGateCleared, setMigrationGateCleared] = useState(false);
  const previousScopeKey = useRef(`${entityType}|${scope}`);
  useEffect(() => {
    const scopeKey = `${entityType}|${scope}`;
    if (previousScopeKey.current !== scopeKey) {
      previousScopeKey.current = scopeKey;
      setMigrationGateCleared(false);
    }
  }, [entityType, scope]);

  const depsQueryRef = useQueryLoading<SubTypeWorkflowDependenciesQuery>(workflowDependenciesQuery,
    {
      memberFilters: memberIds.length
        ? ({ mode: 'and' as const, filters: [{ key: ['id'], values: memberIds }], filterGroups: [] })
        : null,
    },
  );

  if (!workflowDefinition && !migrationGateCleared) {
    return (
      <Suspense fallback={<Loader />}>
        <WorkflowMigrationConfirmDialog
          entityType={entityType}
          scope={scope}
          onConfirm={() => {
            setMigrationGateCleared(true);
            onRefetch();
          }}
          onCancel={() => setMigrationGateCleared(true)}
          onNoLegacyData={() => setMigrationGateCleared(true)}
        />
      </Suspense>
    );
  }

  if (!depsQueryRef) return <Loader />;

  return (
    <Suspense fallback={<Loader />}>
      <Workflow
        queryRef={queryRef}
        depsQueryRef={depsQueryRef}
        onRefetch={onRefetch}
        entityType={entityType}
        canSwitchScope={canSwitchScope}
        scope={scope}
        onScopeChange={onScopeChange}
      />
    </Suspense>
  );
};

interface SubTypeWorkflowProps {
  entityType: string;
}

const SubTypeWorkflow = ({ entityType }: SubTypeWorkflowProps) => {
  const outletContext = useOutletContext<SubTypeOutletContext | undefined>();
  const { settings } = useContext(UserContext);
  const isEnterpriseEdition = !!settings?.platform_enterprise_edition?.license_validated;
  const canSwitchScope = outletContext?.subType
    ? hasRequestAccessWorkflowConfig(outletContext.subType, isEnterpriseEdition)
    : false;

  const [scope, setScope] = useState<StatusScopeEnum>(StatusScopeEnum.GLOBAL);

  const [workflowQueryRef, loadWorkflowQuery] = useQueryLoadingWithLoadQuery<SubTypeWorkflowQuery>(
    workflowQuery,
    { entityType, scope, allowDraft: entityType === 'DraftWorkspace' },
    { fetchPolicy: 'network-only' },
  );

  const handleRefetch = useCallback(() => {
    loadWorkflowQuery(
      { entityType, scope, allowDraft: entityType === 'DraftWorkspace' },
      { fetchPolicy: 'network-only' },
    );
  }, [loadWorkflowQuery, entityType, scope]);

  const handleScopeChange = useCallback((newScope: StatusScopeEnum) => {
    setScope(newScope);
  }, []);

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
              canSwitchScope={canSwitchScope}
              scope={scope}
              onScopeChange={handleScopeChange}
            />
          </ReactFlowProvider>
        </div>
      </ErrorBoundary>
    </Suspense>
  );
};

export default SubTypeWorkflow;
