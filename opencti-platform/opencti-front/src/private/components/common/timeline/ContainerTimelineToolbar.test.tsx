import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ContainerTimelineToolbar from './ContainerTimelineToolbar';
import { parseTimelineViewState, TIMELINE_KINDS, TIMELINE_LANES } from './timelineUtils';

const renderToolbar = (kinds: string[]) => {
  const onChange = vi.fn();
  const state = { ...parseTimelineViewState(new URLSearchParams(), { grouping: 'day', zoom: 'fit' }), kinds };
  const rendered = testRender(
    <ContainerTimelineToolbar
      state={state}
      onChange={onChange}
      enabledLanes={TIMELINE_LANES}
      canEdit={true}
      liveUpdates={0}
      regenerating={false}
      onRefresh={vi.fn()}
      onAdd={vi.fn()}
      onExport={vi.fn()}
      onOpenSettings={vi.fn()}
      onRegenerate={vi.fn()}
      onZoom={vi.fn()}
      onFit={vi.fn()}
    />,
  );
  return { ...rendered, onChange };
};

describe('ContainerTimelineToolbar', () => {
  it('names every kind of the kinds filter, shows which are selected and toggles them', async () => {
    const { user, onChange } = renderToolbar(['sighting']);
    await user.click(screen.getByRole('button', { name: 'Kinds (1)' }));
    expect(screen.getAllByRole('menuitemcheckbox')).toHaveLength(TIMELINE_KINDS.length);
    expect(screen.getByRole('menuitemcheckbox', { name: 'Sighting' })).toHaveAttribute('aria-checked', 'true');
    const malwareSeen = screen.getByRole('menuitemcheckbox', { name: 'Malware seen' });
    expect(malwareSeen).toHaveAttribute('aria-checked', 'false');
    await user.click(malwareSeen);
    expect(onChange).toHaveBeenCalledWith({ kinds: ['sighting', 'malware_seen'] });
  });
});
