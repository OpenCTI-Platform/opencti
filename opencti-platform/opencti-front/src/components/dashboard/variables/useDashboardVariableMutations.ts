import { graphql } from 'react-relay';
import { useCallback } from 'react';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { normalizeFilterGroupForBackend } from '../../../utils/filters/filtersUtils';
import type { DashboardVariable } from '../dashboard-types';
import type {
  useDashboardVariableMutationsUpsertMutation,
  useDashboardVariableMutationsUpsertMutation$variables,
} from './__generated__/useDashboardVariableMutationsUpsertMutation.graphql';
import type { useDashboardVariableMutationsDeleteMutation } from './__generated__/useDashboardVariableMutationsDeleteMutation.graphql';

const upsertMutation = graphql`
  mutation useDashboardVariableMutationsUpsertMutation($id: ID!, $input: DashboardVariableInput!) {
    workspaceVariableUpsert(id: $id, input: $input) {
      ...CustomDashboard_workspace
    }
  }
`;

const deleteMutation = graphql`
  mutation useDashboardVariableMutationsDeleteMutation($id: ID!, $variableId: ID!) {
    workspaceVariableDelete(id: $id, variableId: $variableId) {
      ...CustomDashboard_workspace
    }
  }
`;

type UpsertInput = useDashboardVariableMutationsUpsertMutation$variables['input'];

export const variableToInput = (variable: DashboardVariable): UpsertInput => ({
  id: variable.id,
  name: variable.name,
  type: variable.type,
  defaultValue: variable.defaultValue,
  ...(variable.type === 'vocabulary' && { vocabularyCategory: variable.vocabularyCategory as UpsertInput['vocabularyCategory'] }),
  ...(variable.type === 'killChainPhase' && { killChainName: variable.killChainName }),
  ...(variable.type === 'entity' && { entityTypes: variable.entityTypes }),
  restriction: {
    mode: variable.restriction.mode,
    ...(variable.restriction.mode === 'selection' && { values: variable.restriction.values }),
    ...(variable.restriction.mode === 'filters' && {
      filters: JSON.stringify(normalizeFilterGroupForBackend(variable.restriction.filters)),
    }),
  },
});

export const useDashboardVariableMutations = (workspaceId: string) => {
  const [commitUpsert, upserting] = useApiMutation<useDashboardVariableMutationsUpsertMutation>(upsertMutation);
  const [commitDelete, deleting] = useApiMutation<useDashboardVariableMutationsDeleteMutation>(deleteMutation);

  const upsert = useCallback((variable: DashboardVariable) => new Promise<void>((resolve, reject) => {
    commitUpsert({
      variables: { id: workspaceId, input: variableToInput(variable) },
      onCompleted: () => resolve(),
      onError: reject,
    });
  }), [commitUpsert, workspaceId]);

  const remove = useCallback((variableId: string) => new Promise<void>((resolve, reject) => {
    commitDelete({
      variables: { id: workspaceId, variableId },
      onCompleted: () => resolve(),
      onError: reject,
    });
  }), [commitDelete, workspaceId]);

  // Sequential on purpose: the server serializes writes anyway and this avoids a burst of concurrent requests.
  // Stops on the first error (the rejection propagates to the caller).
  const setAsDefaults = useCallback(async (variables: DashboardVariable[], values: ReadonlyMap<string, string>) => {
    const changed = variables.filter((variable) => values.has(variable.id) && values.get(variable.id) !== variable.defaultValue);
    for (const variable of changed) {
      await upsert({ ...variable, defaultValue: values.get(variable.id) as string });
    }
  }, [upsert]);

  return { upsert, remove, setAsDefaults, isSubmitting: upserting || deleting };
};
