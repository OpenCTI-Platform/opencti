import { graphql } from 'react-relay';
import { useCallback } from 'react';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import type {
  useDashboardPresetMutationsUpsertMutation,
  useDashboardPresetMutationsUpsertMutation$variables,
} from './__generated__/useDashboardPresetMutationsUpsertMutation.graphql';
import type { useDashboardPresetMutationsDeleteMutation } from './__generated__/useDashboardPresetMutationsDeleteMutation.graphql';

const upsertMutation = graphql`
  mutation useDashboardPresetMutationsUpsertMutation($id: ID!, $input: DashboardPresetInput!) {
    workspacePresetUpsert(id: $id, input: $input) {
      presets {
        id
        name
      }
      ...CustomDashboard_workspace
    }
  }
`;

const deleteMutation = graphql`
  mutation useDashboardPresetMutationsDeleteMutation($id: ID!, $presetId: ID!) {
    workspacePresetDelete(id: $id, presetId: $presetId) {
      ...CustomDashboard_workspace
    }
  }
`;

export type DashboardPresetUpsertInput = useDashboardPresetMutationsUpsertMutation$variables['input'];

export const useDashboardPresetMutations = (workspaceId: string) => {
  const [commitUpsert, upserting] = useApiMutation<useDashboardPresetMutationsUpsertMutation>(upsertMutation);
  const [commitDelete, deleting] = useApiMutation<useDashboardPresetMutationsDeleteMutation>(deleteMutation);

  // Resolves with the id of the saved preset (the one given, or the one the server generated).
  const upsert = useCallback((input: DashboardPresetUpsertInput) => new Promise<string>((resolve, reject) => {
    commitUpsert({
      variables: { id: workspaceId, input },
      onCompleted: (response) => {
        const presets = response.workspacePresetUpsert?.presets ?? [];
        const saved = input.id ? presets.find((preset) => preset.id === input.id) : presets.find((preset) => preset.name === input.name.trim());
        resolve(saved?.id ?? input.id ?? '');
      },
      onError: reject,
    });
  }), [commitUpsert, workspaceId]);

  const remove = useCallback((presetId: string) => new Promise<void>((resolve, reject) => {
    commitDelete({
      variables: { id: workspaceId, presetId },
      onCompleted: () => resolve(),
      onError: reject,
    });
  }), [commitDelete, workspaceId]);

  return { upsert, remove, isSubmitting: upserting || deleting };
};
