import React, { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ContainerTimelineToolbar from './ContainerTimelineToolbar';
import { parseTimelineViewState, TIMELINE_KINDS, TIMELINE_LANES, type TimelineViewState } from './timelineUtils';

const baseState = (patch: Partial<TimelineViewState> = {}): TimelineViewState => ({
  ...parseTimelineViewState(new URLSearchParams(), { grouping: 'day', zoom: 'fit' }),
  ...patch,
});

const toolbarProps = (state: TimelineViewState, onChange: (patch: Partial<TimelineViewState>) => void, enabledLanes: readonly string[] = TIMELINE_LANES) => ({
  state,
  onChange,
  enabledLanes,
  canEdit: true,
  liveUpdates: 0,
  regenerating: false,
  onRefresh: vi.fn(),
  onAdd: vi.fn(),
  onExport: vi.fn(),
  onOpenSettings: vi.fn(),
  onRegenerate: vi.fn(),
  onZoom: vi.fn(),
  onFit: vi.fn(),
});

// Holds the view state like the timeline does, with an outside reset like "Clear filters"
const StatefulToolbar = ({ initial }: { initial: TimelineViewState }) => {
  const [state, setState] = useState(initial);
  return (
    <>
      <button type="button" onClick={() => setState((current) => ({ ...current, search: '' }))}>Reset from outside</button>
      <ContainerTimelineToolbar {...toolbarProps(state, (patch) => setState((current) => ({ ...current, ...patch })))} />
    </>
  );
};

describe('ContainerTimelineToolbar', () => {
  it('names every kind of the kinds filter, shows which are selected and toggles them', async () => {
    const onChange = vi.fn();
    const { user } = testRender(<ContainerTimelineToolbar {...toolbarProps(baseState({ kinds: ['sighting'] }), onChange)} />);
    await user.click(screen.getByRole('button', { name: 'Kinds (1)' }));
    expect(screen.getAllByRole('menuitemcheckbox')).toHaveLength(TIMELINE_KINDS.length);
    expect(screen.getByRole('menuitemcheckbox', { name: 'Sighting' })).toHaveAttribute('aria-checked', 'true');
    const malwareSeen = screen.getByRole('menuitemcheckbox', { name: 'Malware seen' });
    expect(malwareSeen).toHaveAttribute('aria-checked', 'false');
    await user.click(malwareSeen);
    expect(onChange).toHaveBeenCalledWith({ kinds: ['sighting', 'malware_seen'] });
  });

  it('shows every enabled lane selected when the lane kept in the URL was disabled since', () => {
    const enabled = TIMELINE_LANES.filter((lane) => lane !== 'evidence');
    testRender(<ContainerTimelineToolbar {...toolbarProps(baseState({ lanes: ['evidence'] }), vi.fn(), enabled)} />);
    expect(screen.queryByTestId('timeline-lane-evidence')).toBeNull();
    enabled.forEach((lane) => expect(screen.getByTestId(`timeline-lane-${lane}`)).toHaveAttribute('aria-checked', 'true'));
  });

  it('keeps the search field in line with the view state', async () => {
    const { user } = testRender(<StatefulToolbar initial={baseState({ search: 'beacon' })} />);
    const search = screen.getByRole('searchbox', { name: 'Search the timeline' });
    expect(search).toHaveValue('beacon');
    await user.click(screen.getByRole('button', { name: 'Reset from outside' }));
    expect(search).toHaveValue('');
    await user.type(search, 'loader{Enter}');
    expect(search).toHaveValue('loader');
  });
});
