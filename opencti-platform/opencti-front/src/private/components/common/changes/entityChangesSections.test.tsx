import { screen } from '@testing-library/react';
import React from 'react';
import { describe, expect, it } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import { CHANGES_SECTION_AS_OF, CHANGES_SECTION_COMPARE } from '../time_machine/timeMachineUtils';
import EntityChangesTab from './EntityChangesTab';
import { ENTITY_CHANGES_SECTIONS, type EntityChangesSectionProps } from './entityChangesSections';

// The registered sections, each with a light content, to check their order and the links into them
const SECTIONS = ENTITY_CHANGES_SECTIONS.map((registered) => ({
  ...registered,
  Component: ({ entityId }: EntityChangesSectionProps) => <div>{`${registered.key} of ${entityId}`}</div>,
}));
const BASE_PATH = '/dashboard/threats/intrusion_sets/entity-1';

const renderTab = (search: string) => testRender(
  <EntityChangesTab entityId="entity-1" basePath={BASE_PATH} sections={SECTIONS} />,
  { route: `${BASE_PATH}/changes${search}` },
);

describe('Entity Changes tab sections', () => {
  it('starts with comparing two dates, then viewing the entity as of a date', () => {
    expect(ENTITY_CHANGES_SECTIONS.slice(0, 2).map(({ key }) => key)).toEqual([CHANGES_SECTION_COMPARE, CHANGES_SECTION_AS_OF]);
  });

  it('opens the comparison by default', async () => {
    renderTab('');
    expect(await screen.findByText(`${CHANGES_SECTION_COMPARE} of entity-1`)).toBeInTheDocument();
  });

  it('opens the as-of view for a link carrying a date without a section', async () => {
    renderTab('?asOf=2026-07-01T00:00:00.000Z');
    expect(await screen.findByText(`${CHANGES_SECTION_AS_OF} of entity-1`)).toBeInTheDocument();
    expect(screen.queryByText(`${CHANGES_SECTION_COMPARE} of entity-1`)).not.toBeInTheDocument();
  });

  it('keeps the section named in the link over its date', async () => {
    renderTab(`?section=${CHANGES_SECTION_COMPARE}&asOf=2026-07-01T00:00:00.000Z`);
    expect(await screen.findByText(`${CHANGES_SECTION_COMPARE} of entity-1`)).toBeInTheDocument();
  });

  it('opens the comparison for a link carrying an invalid date', async () => {
    renderTab('?asOf=not-a-date');
    expect(await screen.findByText(`${CHANGES_SECTION_COMPARE} of entity-1`)).toBeInTheDocument();
  });
});
