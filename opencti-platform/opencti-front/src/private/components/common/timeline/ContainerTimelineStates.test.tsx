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

  it('points to the timeline settings, not to the filters, when the settings hide every event', () => {
    const handlers = { ...actions(), onOpenSettings: vi.fn() };
    testRender(<ContainerTimelineEmptyState filtered={false} hiddenBySettings={true} canEdit={true} regenerating={false} {...handlers} />);
    expect(screen.getByRole('status')).toHaveTextContent('Every event of the case is in a lane or a kind the timeline settings hide.');
    fireEvent.click(screen.getByRole('button', { name: 'Timeline settings' }));
    expect(handlers.onOpenSettings).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('button', { name: 'Clear filters' })).toBeNull();
  });

  it('only explains the settings to readers who cannot change them', () => {
    testRender(<ContainerTimelineEmptyState filtered={false} hiddenBySettings={true} canEdit={false} regenerating={false} {...actions()} onOpenSettings={vi.fn()} />);
    expect(screen.getByRole('status')).toHaveTextContent('Every event of the case is in a lane or a kind the timeline settings hide.');
    expect(screen.queryByRole('button')).toBeNull();
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

const requestError = (code: string) => Object.assign(new Error('request failed'), { res: { status: 200, errors: [{ extensions: { code } }] } });
const httpError = (status: number) => Object.assign(new Error('request failed'), { res: { status } });

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

  it.each([
    ['a lock of the server', requestError('LOCK_ERROR')],
    ['an unavailable server', httpError(503)],
  ])('offers a retry after %s', (_, error) => {
    failure = error;
    renderBoundary();
    expect(screen.getByTestId('timeline-error')).toBeInTheDocument();
  });

  it.each([
    ['a session error', requestError('AUTH_REQUIRED')],
    ['a second factor to provide', requestError('OTP_REQUIRED')],
    ['a revoked access', requestError('FORBIDDEN_ACCESS')],
    ['a container that no longer exists', requestError('RESOURCE_NOT_FOUND')],
    ['a rejected request', httpError(403)],
    ['an error of the code', new Error('rendering failed')],
  ])('leaves %s to the page error boundaries', (_, error) => {
    failure = error;
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
