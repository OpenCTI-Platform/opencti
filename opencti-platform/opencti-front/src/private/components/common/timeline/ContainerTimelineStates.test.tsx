import React, { Component, type ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import {
  ContainerTimelineEmptyState,
  ContainerTimelineErrorBoundary,
  ContainerTimelineErrorState,
  ContainerTimelineSkeleton,
  TIMELINE_DOCUMENTATION_URL,
} from './ContainerTimelineStates';

const actions = () => ({ onAdd: vi.fn(), onRegenerate: vi.fn(), onClearFilters: vi.fn() });

describe('ContainerTimelineEmptyState', () => {
  it('explains what fills a new timeline and offers editors to add an event or regenerate', () => {
    const handlers = actions();
    testRender(<ContainerTimelineEmptyState filtered={false} canEdit={true} regenerating={false} {...handlers} />);
    expect(screen.getByRole('status')).toHaveTextContent('This timeline has no event yet');
    expect(screen.getByRole('link', { name: 'Read the documentation' })).toHaveAttribute('href', TIMELINE_DOCUMENTATION_URL);
    fireEvent.click(screen.getByRole('button', { name: 'Add an event' }));
    fireEvent.click(screen.getByRole('button', { name: 'Regenerate the timeline' }));
    expect(handlers.onAdd).toHaveBeenCalledTimes(1);
    expect(handlers.onRegenerate).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('button', { name: 'Clear filters' })).toBeNull();
  });

  it('keeps the documentation link but offers no contribution to readers who cannot edit the case', () => {
    testRender(<ContainerTimelineEmptyState filtered={false} canEdit={false} regenerating={false} {...actions()} />);
    expect(screen.queryByRole('button')).toBeNull();
    expect(screen.getByRole('link', { name: 'Read the documentation' })).toBeInTheDocument();
  });

  it('offers to clear the filters when they hide every event', () => {
    const handlers = actions();
    testRender(<ContainerTimelineEmptyState filtered={true} canEdit={true} regenerating={false} {...handlers} />);
    expect(screen.getByRole('status')).toHaveTextContent('No event matches the current filters');
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(handlers.onClearFilters).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('button', { name: 'Add an event' })).toBeNull();
  });

  it('disables the regeneration while one is running', () => {
    testRender(<ContainerTimelineEmptyState filtered={false} canEdit={true} regenerating={true} {...actions()} />);
    expect(screen.getByRole('button', { name: 'Regenerate the timeline' })).toBeDisabled();
  });
});

describe('ContainerTimelineErrorState', () => {
  it('explains that the events could not be loaded and offers to retry', () => {
    const onRetry = vi.fn();
    testRender(<ContainerTimelineErrorState onRetry={onRetry} />);
    expect(screen.getByRole('alert')).toHaveTextContent('The timeline could not be loaded');
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});

class PageBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    return this.state.failed ? <div>page error</div> : this.props.children;
  }
}

const requestError = (code: string) => Object.assign(new Error('request failed'), { res: { errors: [{ extensions: { code } }] } });

describe('ContainerTimelineErrorBoundary', () => {
  let failure: Error | null = null;
  const Events = () => {
    if (failure) throw failure;
    return <div>events</div>;
  };
  const renderBoundary = (onRetry = vi.fn()) => testRender(
    <PageBoundary>
      <ContainerTimelineErrorBoundary onRetry={onRetry}>
        <Events />
      </ContainerTimelineErrorBoundary>
    </PageBoundary>,
  );

  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
  });
  afterEach(() => {
    failure = null;
    vi.restoreAllMocks();
  });

  it('shows the error panel when the request fails, and the events again after a retry', () => {
    failure = requestError('DATABASE_ERROR');
    const onRetry = vi.fn(() => {
      failure = null;
    });
    renderBoundary(onRetry);
    expect(screen.getByTestId('timeline-error')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(onRetry).toHaveBeenCalledTimes(1);
    expect(screen.getByText('events')).toBeInTheDocument();
  });

  it('leaves session errors and errors of the code to the page error boundary', () => {
    failure = requestError('AUTH_REQUIRED');
    const { unmount } = renderBoundary();
    expect(screen.getByText('page error')).toBeInTheDocument();
    unmount();
    failure = new Error('rendering failed');
    renderBoundary();
    expect(screen.getByText('page error')).toBeInTheDocument();
    expect(screen.queryByTestId('timeline-error')).toBeNull();
  });
});

describe('ContainerTimelineSkeleton', () => {
  it('announces the loading of the timeline', () => {
    testRender(<ContainerTimelineSkeleton />);
    expect(screen.getByRole('progressbar', { name: 'Loading the timeline' })).toBeInTheDocument();
  });
});
