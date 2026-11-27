import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import testRender from '../utils/tests/test-render';
import EditEntityControlledDial from './EditEntityControlledDial';
import { getEntityEditionOpener } from './entityEditionOpener';
import useDraftContext from '../utils/hooks/useDraftContext';

vi.mock('../utils/hooks/useDraftContext', () => ({ default: vi.fn(() => null) }));

afterEach(() => {
  vi.mocked(useDraftContext).mockReturnValue(null);
});

describe('EditEntityControlledDial', () => {
  it('registers onOpen while mounted and unregisters on unmount', () => {
    const onOpen = vi.fn();
    const { unmount } = testRender(<EditEntityControlledDial onOpen={onOpen} />);
    getEntityEditionOpener()?.();
    expect(onOpen).toHaveBeenCalledTimes(1);
    unmount();
    expect(getEntityEditionOpener()).toBeNull();
  });

  it('calls the latest onOpen after a re-render without stacking', () => {
    const onOpen = vi.fn();
    const nextOnOpen = vi.fn();
    const { rerender, unmount } = testRender(<EditEntityControlledDial onOpen={onOpen} />);
    rerender(<EditEntityControlledDial onOpen={nextOnOpen} />);
    getEntityEditionOpener()?.();
    expect(nextOnOpen).toHaveBeenCalledTimes(1);
    expect(onOpen).not.toHaveBeenCalled();
    unmount();
    expect(getEntityEditionOpener()).toBeNull();
  });

  it('does not register when the update button is disabled', () => {
    const { unmount } = testRender(<EditEntityControlledDial onOpen={vi.fn()} disabled />);
    expect(getEntityEditionOpener()).toBeNull();
    unmount();
  });

  it('does not register in a draft without edit right', () => {
    vi.mocked(useDraftContext).mockReturnValue({ id: 'draft', currentUserAccessRight: 'view' } as ReturnType<typeof useDraftContext>);
    const { unmount } = testRender(<EditEntityControlledDial onOpen={vi.fn()} />);
    expect(getEntityEditionOpener()).toBeNull();
    unmount();
  });
});
