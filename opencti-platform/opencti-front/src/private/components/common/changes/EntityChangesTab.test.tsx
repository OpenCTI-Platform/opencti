import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React from 'react';
import { describe, expect, it } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import EntityChangesTab from './EntityChangesTab';
import { ENTITY_CHANGES_SECTIONS, type EntityChangesSection, type EntityChangesSectionProps } from './entityChangesSections';

const section = (key: string, label: string): EntityChangesSection => ({
  key,
  label,
  Component: ({ entityId, basePath }: EntityChangesSectionProps) => <div>{`${key} of ${entityId} at ${basePath}`}</div>,
});

const SECTIONS = [section('compare', 'Compare dates'), section('merges', 'Merges')];
const BASE_PATH = '/dashboard/threats/intrusion_sets/entity-1';

describe('Entity Changes tab', () => {
  it('registers the Merges section', () => {
    expect(ENTITY_CHANGES_SECTIONS.map(({ key }) => key)).toContain('merges');
  });

  it('opens the first section by default, for the entity', async () => {
    testRender(<EntityChangesTab entityId="entity-1" basePath={BASE_PATH} sections={SECTIONS} />, { route: `${BASE_PATH}/changes` });
    expect(await screen.findByText(`compare of entity-1 at ${BASE_PATH}`)).toBeInTheDocument();
  });

  it('opens the section named in the URL and switches sections from the tabs, keeping the other parameters', async () => {
    testRender(<EntityChangesTab entityId="entity-1" basePath={BASE_PATH} sections={SECTIONS} />, { route: `${BASE_PATH}/changes?section=merges&record=record-1` });
    expect(await screen.findByText(`merges of entity-1 at ${BASE_PATH}`)).toBeInTheDocument();
    await userEvent.click(screen.getByTestId('entity-changes-section-compare'));
    expect(await screen.findByText(`compare of entity-1 at ${BASE_PATH}`)).toBeInTheDocument();
    expect(window.location.search).toContain('section=compare');
    expect(window.location.search).toContain('record=record-1');
  });

  it('falls back to the first section for an unknown section', async () => {
    testRender(<EntityChangesTab entityId="entity-1" basePath={BASE_PATH} sections={SECTIONS} />, { route: `${BASE_PATH}/changes?section=unknown` });
    expect(await screen.findByText(`compare of entity-1 at ${BASE_PATH}`)).toBeInTheDocument();
  });
});
