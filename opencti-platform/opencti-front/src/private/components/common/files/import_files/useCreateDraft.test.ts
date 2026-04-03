import { describe, expect, it, vi, beforeEach } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import useCreateDraft from './useCreateDraft';
import { DraftAddInput } from '@components/drafts/DraftCreation';
import { UseMutationConfig } from 'react-relay';
import { DraftCreationMutation } from '@components/drafts/__generated__/DraftCreationMutation.graphql';

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------
const minimalDraftValues: DraftAddInput = {
  name: 'My Draft',
  description: 'A description',
  objectAssignee: [],
  objectParticipant: [],
  createdBy: undefined,
  authorized_members: undefined,
};

const makeHook = (
  mockCommit: ReturnType<typeof vi.fn>,
  mockSetDraftId: ReturnType<typeof vi.fn> = vi.fn(),
) => renderHook(() => useCreateDraft(
  mockCommit as unknown as (args: UseMutationConfig<DraftCreationMutation>) => void,
  mockSetDraftId as unknown as (id?: string) => void,
));

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('useCreateDraft', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('when the mutation succeeds', () => {
    it('should return the new draft id', async () => {
      const mockCommit = vi.fn().mockImplementation(({ onCompleted }) => {
        onCompleted({ draftWorkspaceAdd: { id: 'draft-abc' } }, null);
      });

      const { result } = makeHook(mockCommit);

      let returnedId: string | undefined;
      await act(async () => {
        returnedId = await result.current(minimalDraftValues);
      });

      expect(returnedId).toBe('draft-abc');
    });

    it('should call setDraftId with the id returned by the mutation', async () => {
      const mockSetDraftId = vi.fn();
      const mockCommit = vi.fn().mockImplementation(({ onCompleted }) => {
        onCompleted({ draftWorkspaceAdd: { id: 'draft-abc' } }, null);
      });

      const { result } = makeHook(mockCommit, mockSetDraftId);

      await act(async () => {
        await result.current(minimalDraftValues);
      });

      expect(mockSetDraftId).toHaveBeenCalledWith('draft-abc');
    });

    it('should build the correct mutation variables from DraftAddInput', async () => {
      const mockCommit = vi.fn().mockImplementation(({ onCompleted }) => {
        onCompleted({ draftWorkspaceAdd: { id: 'draft-abc' } }, null);
      });

      const values: DraftAddInput = {
        name: 'Test Draft',
        description: 'Test desc',
        objectAssignee: [{ value: 'assignee-1', label: 'Assignee 1' }],
        objectParticipant: [{ value: 'participant-1', label: 'Participant 1' }],
        createdBy: { value: 'author-1', label: 'Author 1' },
        authorized_members: undefined,
      };

      const { result } = makeHook(mockCommit);

      await act(async () => {
        await result.current(values, 'entity-42');
      });

      expect(mockCommit).toHaveBeenCalledWith(
        expect.objectContaining({
          variables: {
            input: {
              name: 'Test Draft',
              description: 'Test desc',
              entity_id: 'entity-42',
              objectAssignee: ['assignee-1'],
              objectParticipant: ['participant-1'],
              createdBy: 'author-1',
              authorized_members: null,
            },
          },
        }),
      );
    });

    it('should pass entity_id when selectedEntityId is provided', async () => {
      const mockCommit = vi.fn().mockImplementation(({ onCompleted }) => {
        onCompleted({ draftWorkspaceAdd: { id: 'draft-xyz' } }, null);
      });

      const { result } = makeHook(mockCommit);

      await act(async () => {
        await result.current(minimalDraftValues, 'entity-456');
      });

      expect(mockCommit).toHaveBeenCalledWith(
        expect.objectContaining({
          variables: expect.objectContaining({
            input: expect.objectContaining({ entity_id: 'entity-456' }),
          }),
        }),
      );
    });

    it('should pass entity_id as undefined when not provided', async () => {
      const mockCommit = vi.fn().mockImplementation(({ onCompleted }) => {
        onCompleted({ draftWorkspaceAdd: { id: 'draft-xyz' } }, null);
      });

      const { result } = makeHook(mockCommit);

      await act(async () => {
        await result.current(minimalDraftValues);
      });

      expect(mockCommit).toHaveBeenCalledWith(
        expect.objectContaining({
          variables: expect.objectContaining({
            input: expect.objectContaining({ entity_id: undefined }),
          }),
        }),
      );
    });

    it('should filter out authorized_members with accessRight "none"', async () => {
      const mockCommit = vi.fn().mockImplementation(({ onCompleted }) => {
        onCompleted({ draftWorkspaceAdd: { id: 'draft-abc' } }, null);
      });

      const values: DraftAddInput = {
        ...minimalDraftValues,
        authorized_members: [
          { value: 'member-1', label: 'Member 1', accessRight: 'view', groupsRestriction: [] },
          { value: 'member-2', label: 'Member 2', accessRight: 'none', groupsRestriction: [] },
          { value: 'member-3', label: 'Member 3', accessRight: 'edit', groupsRestriction: [] },
        ],
      };

      const { result } = makeHook(mockCommit);

      await act(async () => {
        await result.current(values);
      });

      const calledInput = mockCommit.mock.calls[0][0].variables.input;
      expect(calledInput.authorized_members).toHaveLength(2);
      expect(calledInput.authorized_members).toEqual([
        { id: 'member-1', access_right: 'view', groups_restriction_ids: undefined },
        { id: 'member-3', access_right: 'edit', groups_restriction_ids: undefined },
      ]);
    });

    it('should map groups_restriction_ids when groupsRestriction is set', async () => {
      const mockCommit = vi.fn().mockImplementation(({ onCompleted }) => {
        onCompleted({ draftWorkspaceAdd: { id: 'draft-abc' } }, null);
      });

      const values: DraftAddInput = {
        ...minimalDraftValues,
        authorized_members: [
          {
            value: 'member-1',
            label: 'Member 1',
            accessRight: 'view',
            groupsRestriction: [{ value: 'group-1', label: 'Group 1' }],
          },
        ],
      };

      const { result } = makeHook(mockCommit);

      await act(async () => {
        await result.current(values);
      });

      const calledInput = mockCommit.mock.calls[0][0].variables.input;
      expect(calledInput.authorized_members[0].groups_restriction_ids).toEqual(['group-1']);
    });
  });

  describe('when the mutation fails via onError', () => {
    it('should return undefined when the mutation fails (notification is delegated to the caller via useApiMutation)', async () => {
      const mockCommit = vi.fn().mockImplementation(({ onError }) => {
        onError({ res: { errors: [{ message: 'Draft creation failed' }] } });
      });

      const { result } = makeHook(mockCommit);

      let returnedId: string | undefined = 'initial';
      await act(async () => {
        returnedId = await result.current(minimalDraftValues);
      });

      expect(returnedId).toBeUndefined();
    });

    it('should not call setDraftId when the mutation fails', async () => {
      const mockSetDraftId = vi.fn();
      const mockCommit = vi.fn().mockImplementation(({ onError }) => {
        onError({ res: { errors: [{ message: 'Error' }] } });
      });

      const { result } = makeHook(mockCommit, mockSetDraftId);

      await act(async () => {
        await result.current(minimalDraftValues);
      });

      expect(mockSetDraftId).not.toHaveBeenCalled();
    });
  });

  describe('when the mutation fails via onCompleted with errors', () => {
    it('should return undefined when onCompleted receives errors (notification is delegated to the caller via useApiMutation)', async () => {
      const mockCommit = vi.fn().mockImplementation(({ onCompleted }) => {
        onCompleted(null, [{ message: 'Payload error' }]);
      });

      const { result } = makeHook(mockCommit);

      let returnedId: string | undefined = 'initial';
      await act(async () => {
        returnedId = await result.current(minimalDraftValues);
      });

      expect(returnedId).toBeUndefined();
    });

    it('should not call setDraftId when onCompleted receives errors', async () => {
      const mockSetDraftId = vi.fn();
      const mockCommit = vi.fn().mockImplementation(({ onCompleted }) => {
        onCompleted(null, [{ message: 'Payload error' }]);
      });

      const { result } = makeHook(mockCommit, mockSetDraftId);

      await act(async () => {
        await result.current(minimalDraftValues);
      });

      expect(mockSetDraftId).not.toHaveBeenCalled();
    });
  });
});
