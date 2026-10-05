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
    const kinds = screen.getByRole('combobox', { name: 'Event kinds' });
    expect(kinds).toHaveValue('Kinds (1)');
    await user.click(kinds);
    expect(screen.getAllByRole('option')).toHaveLength(TIMELINE_KINDS.length);
    expect(screen.getByRole('option', { name: 'Sighting' })).toHaveAttribute('aria-selected', 'true');
    const malwareSeen = screen.getByRole('option', { name: 'Malware seen' });
    expect(malwareSeen).toHaveAttribute('aria-selected', 'false');
    await user.click(malwareSeen);
    expect(onChange).toHaveBeenCalledWith({ kinds: ['sighting', 'malware_seen'] });
  });

  it('shows every lane when the lane kept in the URL was disabled since, and leaves the disabled lane out', async () => {
    const enabled = TIMELINE_LANES.filter((lane) => lane !== 'evidence');
    const { user } = testRender(<ContainerTimelineToolbar {...toolbarProps(baseState({ lanes: ['evidence'] }), vi.fn(), enabled)} />);
    const lanesFilter = screen.getByRole('combobox', { name: 'Lanes' });
    expect(lanesFilter).toHaveValue('All lanes');
    await user.click(lanesFilter);
    expect(screen.queryByRole('option', { name: 'Evidence' })).toBeNull();
    expect(screen.getAllByRole('option')).toHaveLength(enabled.length);
    screen.getAllByRole('option').forEach((option) => expect(option).toHaveAttribute('aria-selected', 'false'));
  });

  it('counts the lanes picked, adds and removes one, and clears them', async () => {
    const onChange = vi.fn();
    const { user } = testRender(<ContainerTimelineToolbar {...toolbarProps(baseState({ lanes: ['adversary', 'detection'] }), onChange)} />);
    const lanesFilter = screen.getByRole('combobox', { name: 'Lanes' });
    expect(lanesFilter).toHaveValue('Lanes (2)');
    await user.click(lanesFilter);
    await user.click(screen.getByRole('option', { name: 'Detection' }));
    expect(onChange).toHaveBeenLastCalledWith({ lanes: ['adversary'] });
    await user.click(screen.getByRole('option', { name: 'Response' }));
    expect(onChange).toHaveBeenLastCalledWith({ lanes: ['adversary', 'detection', 'response'] });
    await user.click(screen.getByRole('button', { name: 'Clear the lanes' }));
    expect(onChange).toHaveBeenLastCalledWith({ lanes: [] });
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
