import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import { ContainerTimelineEmptyState, ContainerTimelineSkeleton } from './ContainerTimelineStates';

const actions = () => ({ onAdd: vi.fn(), onRegenerate: vi.fn(), onClearFilters: vi.fn() });

describe('ContainerTimelineEmptyState', () => {
  it('explains an empty timeline and offers to add a milestone or regenerate to editors', () => {
    const handlers = actions();
    testRender(<ContainerTimelineEmptyState filtered={false} canEdit={true} regenerating={false} {...handlers} />);
    expect(screen.getByRole('status')).toHaveTextContent('This timeline has no event yet');
    fireEvent.click(screen.getByRole('button', { name: 'Add milestone' }));
    fireEvent.click(screen.getByRole('button', { name: 'Regenerate the timeline' }));
    expect(handlers.onAdd).toHaveBeenCalledTimes(1);
    expect(handlers.onRegenerate).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('button', { name: 'Clear filters' })).toBeNull();
  });

  it('offers no contribution to readers who cannot edit the case', () => {
    testRender(<ContainerTimelineEmptyState filtered={false} canEdit={false} regenerating={false} {...actions()} />);
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('offers to clear the filters when they hide every event', () => {
    const handlers = actions();
    testRender(<ContainerTimelineEmptyState filtered={true} canEdit={true} regenerating={false} {...handlers} />);
    expect(screen.getByRole('status')).toHaveTextContent('No event matches the current filters');
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(handlers.onClearFilters).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('button', { name: 'Add milestone' })).toBeNull();
  });

  it('disables the regeneration while one is running', () => {
    testRender(<ContainerTimelineEmptyState filtered={false} canEdit={true} regenerating={true} {...actions()} />);
    expect(screen.getByRole('button', { name: 'Regenerate the timeline' })).toBeDisabled();
  });
});

describe('ContainerTimelineSkeleton', () => {
  it('announces the loading of the timeline', () => {
    testRender(<ContainerTimelineSkeleton />);
    expect(screen.getByRole('progressbar', { name: 'Loading the timeline' })).toBeInTheDocument();
  });
});
