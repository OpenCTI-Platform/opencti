import { useCallback } from 'react';
import { UseMutationConfig } from 'react-relay';
import { DraftCreationMutation, DraftCreationMutation$data } from '@components/drafts/__generated__/DraftCreationMutation.graphql';
import { DraftAddInput } from '@components/drafts/DraftCreation';
import { MESSAGING$ } from '../../../../../relay/environment';
import { RelayError } from '../../../../../relay/relayTypes';

type CommitCreationMutation = (args: UseMutationConfig<DraftCreationMutation>) => void;

/**
 * Hook encapsulating the draft creation logic.
 *
 * @param commitCreationMutation - The Relay mutation commit function for creating a draft.
 * @param setDraftId - Context setter to store the newly created draft id.
 * @returns An async function that creates a draft and returns its id, or undefined on error.
 */
const useCreateDraft = (
  commitCreationMutation: CommitCreationMutation,
  setDraftId: (id?: string) => void,
) => {
  return useCallback(async (values: DraftAddInput, selectedEntityId?: string): Promise<string | undefined> => {
    try {
      const { draftWorkspaceAdd } = await new Promise<DraftCreationMutation$data>((resolve, reject) => {
        commitCreationMutation({
          variables: {
            input: {
              name: values.name,
              description: values.description,
              entity_id: selectedEntityId,
              objectAssignee: values.objectAssignee.map(({ value }) => value),
              objectParticipant: values.objectParticipant.map(({ value }) => value),
              createdBy: values.createdBy?.value,
              authorized_members: !values.authorized_members
                ? null
                : values.authorized_members
                    .filter((v) => v.accessRight !== 'none')
                    .map((member) => ({
                      id: member.value,
                      access_right: member.accessRight,
                      groups_restriction_ids: member.groupsRestriction?.length > 0
                        ? member.groupsRestriction.map((group) => group.value)
                        : undefined,
                    })),
            },
          },
          onCompleted: (response, errors) => {
            if (errors) {
              reject(errors);
            } else {
              resolve(response);
            }
          },
          onError: (error) => {
            reject(error);
          },
        });
      });

      setDraftId(draftWorkspaceAdd?.id);
      return draftWorkspaceAdd?.id;
    } catch (error) {
      // onError path: error is a RelayError with a .res.errors array
      if (error && typeof error === 'object' && 'res' in error) {
        const { errors } = (error as unknown as RelayError).res;
        MESSAGING$.notifyError(errors.at(0)?.message);
      } else if (Array.isArray(error)) {
        // onCompleted path: error is the PayloadError[] array
        const firstError = error[0] as { message?: string };
        MESSAGING$.notifyError(firstError?.message);
      }
      return undefined;
    }
  }, [commitCreationMutation, setDraftId]);
};

export default useCreateDraft;
