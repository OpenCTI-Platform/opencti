import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React, { lazy } from 'react';
import { describe, expect, it } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import EntityChangesTab from './EntityChangesTab';
import type { EntityChangesView } from './entityChangesViews';
import { ENTITY_CHANGES_VIEWS } from './entityChangesViews';

const view = (key: string, label: string): EntityChangesView => ({
  key,
  label,
  component: lazy(async () => ({ default: ({ entityId }: { entityId: string }) => <div>{`${key} of ${entityId}`}</div> })),
});

const VIEWS = [view('compare', 'Compare dates'), view('merges', 'Merges')];

describe('Entity Changes tab', () => {
  it('registers the Merges view', () => {
    expect(ENTITY_CHANGES_VIEWS.map(({ key }) => key)).toContain('merges');
  });

  it('opens the first view by default, for the entity', async () => {
    testRender(<EntityChangesTab entityId="entity-1" views={VIEWS} />, { route: '/dashboard/threats/intrusion_sets/entity-1/changes' });
    expect(await screen.findByText('compare of entity-1')).toBeInTheDocument();
  });

  it('opens the view named in the URL and switches views from the tabs', async () => {
    testRender(<EntityChangesTab entityId="entity-1" views={VIEWS} />, { route: '/dashboard/threats/intrusion_sets/entity-1/changes?view=merges' });
    expect(await screen.findByText('merges of entity-1')).toBeInTheDocument();
    await userEvent.click(screen.getByTestId('entity-changes-view-compare'));
    expect(await screen.findByText('compare of entity-1')).toBeInTheDocument();
    expect(window.location.search).toContain('view=compare');
  });

  it('falls back to the first view for an unknown view', async () => {
    testRender(<EntityChangesTab entityId="entity-1" views={VIEWS} />, { route: '/dashboard/threats/intrusion_sets/entity-1/changes?view=unknown' });
    expect(await screen.findByText('compare of entity-1')).toBeInTheDocument();
  });
});
