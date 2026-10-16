import React, { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ContainerTimelineToolbar from './ContainerTimelineToolbar';
import { parseTimelineViewState, TIMELINE_KIND_LABELS, TIMELINE_KINDS, TIMELINE_LANES, TIMELINE_VIEW_DEFAULTS, type TimelineViewState } from './timelineUtils';

const baseState = (patch: Partial<TimelineViewState> = {}): TimelineViewState => ({
  ...parseTimelineViewState(new URLSearchParams(), TIMELINE_VIEW_DEFAULTS),
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
  onZoomWindow: vi.fn(),
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
  it('names every event of the events filter, shows which are selected and toggles them', async () => {
    const onChange = vi.fn();
    const { user } = testRender(<ContainerTimelineToolbar {...toolbarProps(baseState({ kinds: ['sighting'] }), onChange)} />);
    const kinds = screen.getByRole('combobox', { name: 'Events' });
    expect(kinds).toHaveValue('Events (1)');
    await user.click(kinds);
    const options = screen.getAllByRole('option');
    expect(options).toHaveLength(TIMELINE_KINDS.length);
    // Each row writes the name of its event next to its check mark, and is named by it
    TIMELINE_KINDS.forEach((kind, index) => {
      expect(options[index]).toBeVisible();
      expect(options[index]).toHaveTextContent(TIMELINE_KIND_LABELS[kind]);
      expect(options[index]).toHaveAccessibleName(TIMELINE_KIND_LABELS[kind]);
    });
    expect(screen.getByRole('option', { name: 'Sighting' })).toHaveAttribute('aria-selected', 'true');
    const malwareSeen = screen.getByRole('option', { name: 'Malware seen' });
    expect(malwareSeen).toHaveAttribute('aria-selected', 'false');
    await user.click(malwareSeen);
    expect(onChange).toHaveBeenCalledWith({ kinds: ['sighting', 'malware_seen'] });
  });

  it('says events, not kinds, and tells the events filter from the sources filter', async () => {
    const onChange = vi.fn();
    const { user } = testRender(<ContainerTimelineToolbar {...toolbarProps(baseState({ kinds: ['sighting'] }), onChange)} />);
    expect(screen.queryByText(/kinds?\b/i)).toBeNull();
    const source = screen.getByRole('combobox', { name: 'Event source' });
    expect(source).toHaveTextContent('All sources');
    await user.click(screen.getByRole('button', { name: 'Clear the event filter' }));
    expect(onChange).toHaveBeenLastCalledWith({ kinds: [] });
  });

  it('reads All events when no event is picked', () => {
    testRender(<ContainerTimelineToolbar {...toolbarProps(baseState(), vi.fn())} />);
    expect(screen.getByRole('combobox', { name: 'Events' })).toHaveValue('All events');
  });

  it('shows the events of a module not installed as inactive, naming what activates them', async () => {
    const { user } = testRender(<ContainerTimelineToolbar {...toolbarProps(baseState(), vi.fn())} inactiveKinds={{ hunt_run: 'Hunts' }} />);
    await user.click(screen.getByRole('combobox', { name: 'Events' }));
    const huntRun = screen.getAllByRole('option').find((option) => option.textContent?.startsWith('Hunt run')) as HTMLElement;
    expect(huntRun).toHaveAttribute('aria-disabled', 'true');
    expect(huntRun).toHaveTextContent('Activates when the Hunts module is installed');
    expect(screen.getByRole('option', { name: 'Sighting' })).not.toHaveAttribute('aria-disabled', 'true');
    expect(screen.getAllByText(/Activates when/)).toHaveLength(1);
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

  it('names the zoom window and the grouping, and fits from the zoom window only', async () => {
    const onZoomWindow = vi.fn();
    const { user } = testRender(<ContainerTimelineToolbar {...toolbarProps(baseState({ zoom: 'week' }), vi.fn())} onZoomWindow={onZoomWindow} />);
    expect(screen.queryByRole('button', { name: 'Fit the timeline' })).toBeNull();
    expect(screen.getByRole('combobox', { name: 'Group events by' })).toBeInTheDocument();
    const zoom = screen.getByRole('combobox', { name: 'Zoom window' });
    expect(zoom).toHaveTextContent('Week');
    await user.click(zoom);
    expect(screen.queryByRole('option', { name: 'Custom window' })).toBeNull();
    await user.click(screen.getByRole('option', { name: 'Fit' }));
    expect(onZoomWindow).toHaveBeenCalledWith('fit');
  });

  it('shows a custom window once the view was panned or zoomed, and goes back to the window picked', async () => {
    const onZoomWindow = vi.fn();
    const { user } = testRender(<ContainerTimelineToolbar {...toolbarProps(baseState({ zoom: 'fit' }), vi.fn())} onZoomWindow={onZoomWindow} customWindow />);
    const zoom = screen.getByRole('combobox', { name: 'Zoom window' });
    expect(zoom).toHaveTextContent('Custom window');
    await user.click(zoom);
    // Fit again, though it was the zoom window already
    await user.click(screen.getByRole('option', { name: 'Fit' }));
    expect(onZoomWindow).toHaveBeenCalledWith('fit');
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
