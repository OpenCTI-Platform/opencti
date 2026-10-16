import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import ContainerTimelineSettingsDrawer from './ContainerTimelineSettingsDrawer';
import { TIMELINE_KIND_LABELS, TIMELINE_KINDS } from './timelineUtils';

const settings = { enabled_lanes: ['adversary', 'response'], hidden_kinds: [] as string[] };

const renderDrawer = (capabilities: string[], inactiveKinds?: Record<string, string>, drawerSettings = settings) => testRender(
  <ContainerTimelineSettingsDrawer
    containerId="case-1"
    entityType="Case-Incident"
    headlineDates={['containment', 'recovery']}
    inactiveKinds={inactiveKinds}
    open={true}
    settings={drawerSettings}
    onClose={vi.fn()}
    onSaved={vi.fn()}
  />,
  { userContext: createMockUserContext({ me: { id: 'user-1', capabilities: capabilities.map((name) => ({ name })) } }) },
);

describe('ContainerTimelineSettingsDrawer headline dates', () => {
  it('shows the headline dates of the type read-only, with a link to their customization', async () => {
    renderDrawer(['SETTINGS_SETCUSTOMIZATION']);
    const section = await screen.findByTestId('timeline-settings-headline-dates');
    expect(within(section).getAllByRole('listitem').map((item) => item.textContent)).toEqual(['Containment', 'Recovery']);
    expect(within(section).queryByRole('checkbox')).toBeNull();
    expect(within(section).getByTestId('timeline-settings-headline-dates-link'))
      .toHaveAttribute('href', '/dashboard/settings/customization/entity_types/Case-Incident/timeline');
  });

  it('names them without a link for users who cannot customize the types', async () => {
    renderDrawer(['KNOWLEDGE_KNUPDATE']);
    const section = await screen.findByTestId('timeline-settings-headline-dates');
    expect(within(section).getAllByRole('listitem')).toHaveLength(2);
    expect(within(section).queryByRole('link')).toBeNull();
  });
});

describe('ContainerTimelineSettingsDrawer display choices', () => {
  it('leaves the zoom, the grouping and the view to each reader', async () => {
    const { user, relayEnv } = renderDrawer(['KNOWLEDGE_KNUPDATE']);
    const drawer = await screen.findByTestId('timeline-settings-drawer');
    expect(drawer).toHaveTextContent('The zoom, the grouping and the view are kept for each reader, in their browser.');
    expect(within(drawer).queryByRole('combobox')).toBeNull();
    await user.click(screen.getByTestId('timeline-settings-save'));
    expect(relayEnv.mock.getMostRecentOperation().request.variables).toEqual({
      containerId: 'case-1',
      input: { enabled_lanes: ['adversary', 'response'], hidden_kinds: [] },
    });
  });
});

describe('ContainerTimelineSettingsDrawer events of a module not installed', () => {
  it('shows them inactive, naming the module that activates them', async () => {
    renderDrawer(['KNOWLEDGE_KNUPDATE'], { hunt_run: 'Hunts', deployment: 'Indicator deployments' });
    await screen.findByTestId('timeline-settings-drawer');
    expect(screen.getByRole('checkbox', { name: /^Hunt run/ })).toBeDisabled();
    expect(screen.getByRole('checkbox', { name: /^Deployment/ })).toBeDisabled();
    expect(screen.getByText('Activates when the Hunts module is installed')).toBeInTheDocument();
    expect(screen.getByText('Activates when the Indicator deployments module is installed')).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Sighting' })).toBeEnabled();
  });

  it('lists them after the events that can exist, so that the rows that can be changed stay together', async () => {
    const inactive = { hunt_run: 'Hunts', deployment: 'Indicator deployments' };
    renderDrawer(['KNOWLEDGE_KNUPDATE'], inactive);
    await screen.findByTestId('timeline-settings-drawer');
    const kinds = screen.getAllByRole('checkbox').slice(-TIMELINE_KINDS.length);
    kinds.slice(0, -2).forEach((checkbox) => expect(checkbox).toBeEnabled());
    const last = TIMELINE_KINDS.filter((kind) => kind in inactive);
    kinds.slice(-2).forEach((checkbox, index) => {
      expect(checkbox).toBeDisabled();
      expect(checkbox).toHaveAccessibleName(new RegExp(`^${TIMELINE_KIND_LABELS[last[index]]}`));
    });
  });

  it('keeps one event that can exist visible, leaving the inactive ones out of the count', async () => {
    const inactive = { hunt_run: 'Hunts' };
    const hidden = TIMELINE_KINDS.filter((kind) => kind !== 'sighting' && kind !== 'hunt_run');
    renderDrawer(['KNOWLEDGE_KNUPDATE'], inactive, { ...settings, hidden_kinds: hidden });
    await screen.findByTestId('timeline-settings-drawer');
    const sighting = screen.getByRole('checkbox', { name: 'Sighting' });
    expect(sighting).not.toBeChecked();
    expect(sighting).toBeDisabled();
  });
});
