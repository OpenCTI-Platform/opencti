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

  it('shows every enabled lane selected when the lane kept in the URL was disabled since', async () => {
    const enabled = TIMELINE_LANES.filter((lane) => lane !== 'evidence');
    const { user } = testRender(<ContainerTimelineToolbar {...toolbarProps(baseState({ lanes: ['evidence'] }), vi.fn(), enabled)} />);
    await user.click(screen.getByRole('button', { name: 'All lanes' }));
    expect(screen.queryByTestId('timeline-lane-evidence')).toBeNull();
    enabled.forEach((lane) => expect(screen.getByTestId(`timeline-lane-${lane}`)).toHaveAttribute('aria-checked', 'true'));
  });

  it('counts the lanes shown and switches one off from the lanes menu', async () => {
    const onChange = vi.fn();
    const { user } = testRender(<ContainerTimelineToolbar {...toolbarProps(baseState({ lanes: ['adversary', 'detection'] }), onChange)} />);
    await user.click(screen.getByRole('button', { name: 'Lanes (2)' }));
    expect(screen.getByRole('menuitemcheckbox', { name: 'Response' })).toHaveAttribute('aria-checked', 'false');
    await user.click(screen.getByRole('menuitemcheckbox', { name: 'Detection' }));
    expect(onChange).toHaveBeenCalledWith({ lanes: ['adversary'] });
  });

  it('names the switches by their labels and puts the primary action last', async () => {
    const onChange = vi.fn();
    const { user } = testRender(<ContainerTimelineToolbar {...toolbarProps(baseState(), onChange)} />);
    await user.click(screen.getByRole('switch', { name: 'Pinned only' }));
    expect(onChange).toHaveBeenCalledWith({ pinnedOnly: true });
    expect(screen.getByRole('switch', { name: 'Show hidden events' })).toBeInTheDocument();
    const firstRow = screen.getByTestId('timeline-toolbar').firstElementChild as HTMLElement;
    expect(firstRow.lastElementChild).toContainElement(screen.getByTestId('timeline-add-milestone'));
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
