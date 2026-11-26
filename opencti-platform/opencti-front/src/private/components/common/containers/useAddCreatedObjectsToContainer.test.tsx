import React, { useImperativeHandle, forwardRef } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, screen } from '@testing-library/react';
import testRender, { createMockUserContext, testRenderHook } from '../../../../utils/tests/test-render';
import { KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE } from '../../../../utils/hooks/capabilities';
import { MESSAGING$ } from '../../../../relay/environment';
import type { ContainerObjectMutationArgs, CreatedObject } from './useContainerObjects';
import { CREATED_OBJECTS_BATCH_DELAY_MS, useAddCreatedObjectsToContainer } from './useAddCreatedObjectsToContainer';

const { addObjectToContainer, removeObjectFromContainer } = vi.hoisted(() => ({
  addObjectToContainer: vi.fn<(args: ContainerObjectMutationArgs) => Promise<void>>(),
  removeObjectFromContainer: vi.fn<(args: ContainerObjectMutationArgs) => Promise<void>>(),
}));

vi.mock('./useContainerObjects', () => ({
  useContainerObjects: () => ({ addObjectToContainer, removeObjectFromContainer }),
}));

// The objects of the container the server knows, whatever the panel loaded
const { serverMemberIds } = vi.hoisted(() => ({ serverMemberIds: { current: [] as string[] } }));

vi.mock('../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../relay/environment')>()),
  fetchQuery: () => ({
    toPromise: () => Promise.resolve({
      container: { objects: { edges: serverMemberIds.current.map((id) => ({ node: { id } })) } },
    }),
  }),
}));

const observable = (id: string): CreatedObject => ({ id, entity_type: 'IPv4-Addr', parent_types: ['Stix-Cyber-Observable'] });

const baseArgs = () => ({
  containerId: 'c1',
  containerType: 'Report',
  isInContainer: vi.fn(() => false),
  onAdded: vi.fn(),
  onRemoved: vi.fn(),
});

type Args = Parameters<typeof useAddCreatedObjectsToContainer>[0];

const renderAddHook = (args: Args) => testRenderHook(() => useAddCreatedObjectsToContainer(args)).hook;

// Lets the batch timer fire and the promises it starts settle
const flushBatch = async () => {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(CREATED_OBJECTS_BATCH_DELAY_MS);
  });
};

// "Update without references" needs this capability
const canSkipReferences = createMockUserContext({ me: { capabilities: [{ name: KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE }] } });

type ReferencesHandle = { onCreated: (o: CreatedObject) => void };
const ReferencesHarness = forwardRef<ReferencesHandle, { args: Args }>(({ args }, ref) => {
  const { onCreated, referencesDialog } = useAddCreatedObjectsToContainer(args);
  useImperativeHandle(ref, () => ({ onCreated }));
  return <>{referencesDialog}</>;
});

describe('useAddCreatedObjectsToContainer', () => {
  let notifySuccess: ReturnType<typeof vi.spyOn>;
  let notifyError: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.useFakeTimers();
    serverMemberIds.current = [];
    vi.mocked(addObjectToContainer).mockReset().mockResolvedValue(undefined);
    vi.mocked(removeObjectFromContainer).mockReset().mockResolvedValue(undefined);
    notifySuccess = vi.spyOn(MESSAGING$, 'notifySuccess').mockImplementation(() => {});
    notifyError = vi.spyOn(MESSAGING$, 'notifyError').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('adds one created object and confirms with an undo action', async () => {
    const args = baseArgs();
    const hook = renderAddHook(args);

    act(() => hook.result.current.onCreated(observable('o1')));
    await flushBatch();

    expect(addObjectToContainer).toHaveBeenCalledWith(expect.objectContaining({ containerId: 'c1', objectId: 'o1' }));
    expect(args.onAdded).toHaveBeenCalledWith(observable('o1'));
    expect(notifySuccess).toHaveBeenCalledOnce();
    const [text, options] = notifySuccess.mock.calls[0];
    expect(text).toContain('created and added to the');
    expect(options.action.label).toBe('Undo');
  });

  it('confirms a bulk creation in its result dialog instead of a message', async () => {
    const hook = renderAddHook(baseArgs());

    act(() => hook.result.current.bulkCreation?.onBulkStart());
    expect(hook.result.current.bulkCreation?.progress?.inProgress).toBe(true);
    act(() => {
      hook.result.current.onCreated(observable('o1'));
      hook.result.current.onCreated(observable('o2'));
      hook.result.current.bulkCreation?.onBulkCompleted();
    });
    await flushBatch();

    expect(addObjectToContainer).toHaveBeenCalledTimes(2);
    expect(notifySuccess).not.toHaveBeenCalled();
    expect(hook.result.current.bulkCreation?.progress).toEqual({ done: 2, total: 2, inProgress: false });
    expect(hook.result.current.bulkCreation?.resultMessage).toContain('2 observables added to the');

    act(() => hook.result.current.bulkCreation?.onBulkEnd());
    expect(hook.result.current.bulkCreation?.progress).toBeNull();
    expect(hook.result.current.bulkCreation?.resultMessage).toBeNull();
  });

  it('counts the objects added after a bulk creation, even a single one', async () => {
    // The other creations of the bulk failed: one object only is added
    const hook = renderAddHook(baseArgs());

    act(() => hook.result.current.bulkCreation?.onBulkStart());
    act(() => {
      hook.result.current.onCreated(observable('o1'));
      hook.result.current.bulkCreation?.onBulkCompleted();
    });
    await flushBatch();

    expect(hook.result.current.bulkCreation?.resultMessage).toContain('1 observables added to the');
  });

  it('adds the objects of a bulk creation together, once all are created', async () => {
    const hook = renderAddHook(baseArgs());

    act(() => hook.result.current.bulkCreation?.onBulkStart());
    act(() => hook.result.current.onCreated(observable('o1')));
    // Long after the first one, other creations may still come: nothing is added yet
    await act(async () => { await vi.advanceTimersByTimeAsync(CREATED_OBJECTS_BATCH_DELAY_MS * 3); });
    expect(addObjectToContainer).not.toHaveBeenCalled();
    expect(hook.result.current.bulkCreation?.progress).toEqual({ done: 0, total: 0, inProgress: true });

    act(() => {
      hook.result.current.onCreated(observable('o2'));
      hook.result.current.bulkCreation?.onBulkCompleted();
    });
    await act(async () => { await vi.runAllTimersAsync(); });

    expect(addObjectToContainer).toHaveBeenCalledTimes(2);
    expect(hook.result.current.bulkCreation?.progress).toEqual({ done: 2, total: 2, inProgress: false });
    expect(hook.result.current.bulkCreation?.resultMessage).toContain('2 observables added to the');
  });

  it('shows the message when the bulk result dialog is closed before the objects are added', async () => {
    const hook = renderAddHook(baseArgs());

    act(() => hook.result.current.bulkCreation?.onBulkStart());
    act(() => {
      hook.result.current.onCreated(observable('o1'));
      hook.result.current.onCreated(observable('o2'));
    });
    act(() => hook.result.current.bulkCreation?.onBulkEnd());
    await flushBatch();

    expect(notifySuccess).toHaveBeenCalledOnce();
    expect(notifySuccess.mock.calls[0][1].action.label).toBe('Undo');
  });

  it('gives no bulk feedback when nothing is added automatically', () => {
    const hook = renderAddHook({ ...baseArgs(), disabled: true });

    expect(hook.result.current.bulkCreation).toBeUndefined();
  });

  it('batches creations arriving within the delay', async () => {
    const hook = renderAddHook(baseArgs());

    act(() => hook.result.current.onCreated(observable('o1')));
    await act(async () => { await vi.advanceTimersByTimeAsync(400); });
    act(() => hook.result.current.onCreated(observable('o2')));
    await act(async () => { await vi.advanceTimersByTimeAsync(400); });
    act(() => hook.result.current.onCreated(observable('o3')));
    await flushBatch();

    expect(addObjectToContainer).toHaveBeenCalledTimes(3);
    expect(notifySuccess).toHaveBeenCalledOnce();
    expect(notifySuccess.mock.calls[0][0]).toContain('3 observables added to the');
  });

  it('skips objects already in the container', async () => {
    const args = { ...baseArgs(), isInContainer: vi.fn((id: string) => id === 'o1') };
    const hook = renderAddHook(args);

    act(() => hook.result.current.onCreated(observable('o1')));
    await flushBatch();

    expect(addObjectToContainer).not.toHaveBeenCalled();
    expect(notifySuccess).toHaveBeenCalledOnce();
    const [text, options] = notifySuccess.mock.calls[0];
    expect(text).toContain('Already in the');
    expect(options).toBeUndefined();
  });

  it('undo removes only the objects added by the batch', async () => {
    const args = { ...baseArgs(), isInContainer: vi.fn((id: string) => id === 'o1') };
    const hook = renderAddHook(args);

    act(() => {
      hook.result.current.onCreated(observable('o1'));
      hook.result.current.onCreated(observable('o2'));
    });
    await flushBatch();
    const { action } = notifySuccess.mock.calls[0][1];
    await act(async () => { action.onClick(); await vi.runAllTimersAsync(); });

    expect(removeObjectFromContainer).toHaveBeenCalledOnce();
    expect(removeObjectFromContainer).toHaveBeenCalledWith(expect.objectContaining({ objectId: 'o2' }));
    expect(args.onRemoved).toHaveBeenCalledWith(observable('o2'));
    expect(notifySuccess.mock.calls[1][0]).toContain('Removed from the');
  });

  it('neither adds nor undoes an object already in the container but not loaded by the panel', async () => {
    // The panel loads only the first objects of the container: it does not know o1
    serverMemberIds.current = ['o1'];
    const args = baseArgs();
    const hook = renderAddHook(args);

    act(() => {
      hook.result.current.onCreated(observable('o1'));
      hook.result.current.onCreated(observable('o2'));
    });
    await flushBatch();

    expect(addObjectToContainer).toHaveBeenCalledOnce();
    expect(addObjectToContainer).toHaveBeenCalledWith(expect.objectContaining({ objectId: 'o2' }));
    const { action } = notifySuccess.mock.calls[0][1];
    await act(async () => { action.onClick(); await vi.runAllTimersAsync(); });
    expect(removeObjectFromContainer).toHaveBeenCalledOnce();
    expect(removeObjectFromContainer).toHaveBeenCalledWith(expect.objectContaining({ objectId: 'o2' }));
  });

  it('reports an add failure and keeps the others', async () => {
    vi.mocked(addObjectToContainer).mockImplementation(({ objectId }) => (objectId === 'o2' ? Promise.reject(new Error('denied')) : Promise.resolve()));
    const args = baseArgs();
    const hook = renderAddHook(args);

    act(() => {
      hook.result.current.onCreated(observable('o1'));
      hook.result.current.onCreated(observable('o2'));
    });
    await flushBatch();

    expect(notifyError).toHaveBeenCalledOnce();
    expect(notifyError.mock.calls[0][0]).toContain('could not be added to the');
    expect(args.onAdded).toHaveBeenCalledOnce();
    expect(args.onAdded).toHaveBeenCalledWith(observable('o1'));
  });

  it('does nothing when disabled', async () => {
    const hook = renderAddHook({ ...baseArgs(), disabled: true });

    act(() => hook.result.current.onCreated(observable('o1')));
    await flushBatch();

    expect(addObjectToContainer).not.toHaveBeenCalled();
    expect(notifySuccess).not.toHaveBeenCalled();
  });

  it('uses the resolved object for onAdded when resolveObject is given', async () => {
    const full = { ...observable('o1'), representative: { main: '10.1.1.1' } };
    const args = { ...baseArgs(), resolveObject: vi.fn(() => Promise.resolve(full)) };
    const hook = renderAddHook(args);

    act(() => hook.result.current.onCreated(observable('o1')));
    await flushBatch();

    expect(args.resolveObject).toHaveBeenCalledWith('o1');
    expect(args.onAdded).toHaveBeenCalledWith(full);
  });

  it('asks references once for the batch when references are enforced', async () => {
    type Handle = { onCreated: (o: CreatedObject) => void };
    const Harness = forwardRef<Handle, { args: Args }>(({ args }, ref) => {
      const { onCreated, referencesDialog } = useAddCreatedObjectsToContainer(args);
      useImperativeHandle(ref, () => ({ onCreated }));
      return <>{referencesDialog}</>;
    });
    const handle = React.createRef<Handle>();
    testRender(<Harness ref={handle} args={{ ...baseArgs(), enableReferences: true }} />, { userContext: canSkipReferences });

    act(() => {
      handle.current?.onCreated(observable('o1'));
      handle.current?.onCreated(observable('o2'));
    });
    await flushBatch();
    expect(addObjectToContainer).not.toHaveBeenCalled();
    expect(screen.getAllByText('Reference modification')).toHaveLength(1);

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Update without references' }));
      // Not runAllTimers: the references dialog keeps a recurring timer
      await vi.advanceTimersByTimeAsync(CREATED_OBJECTS_BATCH_DELAY_MS);
    });

    expect(addObjectToContainer).toHaveBeenCalledTimes(2);
    const [first, second] = vi.mocked(addObjectToContainer).mock.calls.map(([call]) => call);
    expect(first.commitMessage).toBe(second.commitMessage);
    expect(first.references).toEqual(second.references);
  });

  it('asks references once for batches waiting at the same time', async () => {
    const handle = React.createRef<ReferencesHandle>();
    testRender(<ReferencesHarness ref={handle} args={{ ...baseArgs(), enableReferences: true }} />, { userContext: canSkipReferences });

    act(() => handle.current?.onCreated(observable('o1')));
    await flushBatch();
    // A second batch while the dialog is still open
    act(() => handle.current?.onCreated(observable('o2')));
    await flushBatch();
    expect(screen.getAllByText('Reference modification')).toHaveLength(1);

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Update without references' }));
      // Not runAllTimers: the references dialog keeps a recurring timer
      await vi.advanceTimersByTimeAsync(CREATED_OBJECTS_BATCH_DELAY_MS);
    });

    expect(addObjectToContainer).toHaveBeenCalledTimes(2);
    expect(vi.mocked(addObjectToContainer).mock.calls.map(([call]) => call.objectId)).toEqual(['o1', 'o2']);
  });
});

