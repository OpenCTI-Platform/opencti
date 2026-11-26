import React, { useImperativeHandle, forwardRef } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, screen } from '@testing-library/react';
import testRender, { testRenderHook } from '../../../../utils/tests/test-render';
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

describe('useAddCreatedObjectsToContainer', () => {
  let notifySuccess: ReturnType<typeof vi.spyOn>;
  let notifyError: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.useFakeTimers();
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
    testRender(<Harness ref={handle} args={{ ...baseArgs(), enableReferences: true }} />);

    act(() => {
      handle.current?.onCreated(observable('o1'));
      handle.current?.onCreated(observable('o2'));
    });
    await flushBatch();
    expect(addObjectToContainer).not.toHaveBeenCalled();
    expect(screen.getAllByText('Reference modification')).toHaveLength(1);

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Update without references' }));
      await vi.runAllTimersAsync();
    });

    expect(addObjectToContainer).toHaveBeenCalledTimes(2);
    const [first, second] = vi.mocked(addObjectToContainer).mock.calls.map(([call]) => call);
    expect(first.commitMessage).toBe(second.commitMessage);
    expect(first.references).toEqual(second.references);
  });
});
