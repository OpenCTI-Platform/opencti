import React from 'react';
import { beforeEach, describe, expect, it } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router';
import useTimelineViewState from './useTimelineViewState';
import { readTimelineViewPreference, timelineViewPreferenceKey } from './useTimelineViewPreference';
import { TIMELINE_ADD_MILESTONE_PARAM } from './timelineUtils';

const renderViewState = (url: string, containerId = 'case-1') => renderHook(
  () => ({ view: useTimelineViewState(containerId), location: useLocation() }),
  { wrapper: ({ children }) => <MemoryRouter initialEntries={[url]} useTransitions={false}>{children}</MemoryRouter> },
);

const save = (containerId: string, value: unknown) => window.localStorage.setItem(timelineViewPreferenceKey(containerId), JSON.stringify(value));
const saved = (containerId: string) => JSON.parse(window.localStorage.getItem(timelineViewPreferenceKey(containerId)) ?? 'null');

beforeEach(() => {
  window.localStorage.clear();
});

describe('useTimelineViewState', () => {
  it('opens a timeline seen for the first time on the lanes of the whole timeline, grouped by day', () => {
    const { result } = renderViewState('/timeline');
    const { state } = result.current.view;
    expect([state.view, state.grouping, state.zoom]).toEqual(['lanes', 'day', 'fit']);
    expect(result.current.location.search).toBe('');
    expect(saved('case-1')).toBeNull();
  });

  it('saves the zoom, the grouping and the view picked in the toolbar for the next visit of this timeline only', () => {
    const first = renderViewState('/timeline');
    act(() => first.result.current.view.updateState({ grouping: 'week' }));
    act(() => first.result.current.view.updateState({ view: 'list', zoom: 'month' }));
    // Filters are not display choices: they stay in the address of this visit
    act(() => first.result.current.view.updateState({ search: 'phishing' }));
    expect(saved('case-1')).toEqual({ grouping: 'week', view: 'list', zoom: 'month' });
    first.unmount();

    const next = renderViewState('/timeline');
    const { state } = next.result.current.view;
    expect([state.view, state.grouping, state.zoom, state.search]).toEqual(['list', 'week', 'month', '']);
    next.unmount();

    const other = renderViewState('/timeline', 'case-2');
    expect(other.result.current.view.state.grouping).toBe('day');
  });

  it('names the saved choices in the address on opening, so that a link copied right away shows the same view', () => {
    save('case-1', { grouping: 'week', view: 'list' });
    const { result } = renderViewState('/timeline?search=phishing');
    const params = new URLSearchParams(result.current.location.search);
    expect(params.get('search')).toBe('phishing');
    expect(params.get('grouping')).toBe('week');
    expect(params.get('view')).toBe('list');
    // Still the first-visit zoom: nothing to name
    expect(params.has('zoom')).toBe(false);
  });

  it('opens a shared link as it was sent, without changing what the reader saved', () => {
    save('case-1', { grouping: 'week', zoom: 'month' });
    const { result } = renderViewState('/timeline?grouping=hour');
    const { state } = result.current.view;
    expect(state.grouping).toBe('hour');
    // What the link does not name comes from the reader's own choices
    expect(state.zoom).toBe('month');
    expect(saved('case-1')).toEqual({ grouping: 'week', zoom: 'month' });
  });

  it('goes back to the first-visit grouping when the reader picks it again', () => {
    save('case-1', { grouping: 'week' });
    const { result } = renderViewState('/timeline');
    act(() => result.current.view.updateState({ grouping: 'day' }));
    expect(result.current.view.state.grouping).toBe('day');
    expect(new URLSearchParams(result.current.location.search).has('grouping')).toBe(false);
    expect(saved('case-1')).toEqual({ grouping: 'day' });
  });

  it('drops from the address the form asked for by the overview card, once opened', () => {
    const { result } = renderViewState(`/timeline?${TIMELINE_ADD_MILESTONE_PARAM}=true&lanes=response`);
    expect(result.current.view.searchParams.has(TIMELINE_ADD_MILESTONE_PARAM)).toBe(false);
    expect(result.current.location.search).toBe('?lanes=response');
  });
});

describe('readTimelineViewPreference', () => {
  it('reads nothing from a broken or outdated saved value', () => {
    window.localStorage.setItem(timelineViewPreferenceKey('case-1'), '{broken');
    expect(readTimelineViewPreference('case-1')).toEqual({});
    save('case-1', { view: 'gantt', grouping: 'week', zoom: 'decade' });
    expect(readTimelineViewPreference('case-1')).toEqual({ grouping: 'week' });
  });
});
