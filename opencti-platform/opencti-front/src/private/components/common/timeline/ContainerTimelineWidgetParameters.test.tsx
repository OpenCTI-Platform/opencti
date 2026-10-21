import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ContainerTimelineWidgetParameters from './ContainerTimelineWidgetParameters';

const mockFetchQuery = vi.fn();

vi.mock('../../../../relay/environment', () => ({
  fetchQuery: (...args: unknown[]) => mockFetchQuery(...args),
  MESSAGING$: { messages$: { subscribe: vi.fn() } },
}));

const selectedCase = { stixDomainObject: { id: 'case-1', entity_type: 'Case-Incident', representative: { main: 'Ransomware case' } } };

describe('ContainerTimelineWidgetParameters', () => {
  it('asks for the incident or case of a dashboard widget', async () => {
    mockFetchQuery.mockReset();
    mockFetchQuery.mockReturnValue({ toPromise: () => Promise.resolve(selectedCase) });
    testRender(<ContainerTimelineWidgetParameters parameters={{ container_id: 'case-1' }} onChange={vi.fn()} />);
    expect(screen.getByText('Incident or case')).toBeInTheDocument();
    await waitFor(() => expect(mockFetchQuery).toHaveBeenCalledTimes(1));
    expect(screen.getByText('Time window')).toBeInTheDocument();
  });

  it('keeps only the lanes and the window in a custom view, which shows the timeline of the entity it is opened on', () => {
    mockFetchQuery.mockReset();
    testRender(<ContainerTimelineWidgetParameters parameters={{ container_id: 'case-1' }} onChange={vi.fn()} showContainer={false} />);
    expect(screen.queryByText('Incident or case')).not.toBeInTheDocument();
    expect(mockFetchQuery).not.toHaveBeenCalled();
    expect(screen.getByText('Lanes (all when none is selected)')).toBeInTheDocument();
    expect(screen.getByText('Time window')).toBeInTheDocument();
  });
});
