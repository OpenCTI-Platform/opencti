import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import Incident from './Incident';
import type { Incident_incident$key } from './__generated__/Incident_incident.graphql';

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    useFragment: (_fragment: unknown, data: unknown) => data,
  };
});

vi.mock('@components/common/stix_core_relationships/CreateRelationshipContextProvider', () => ({
  useInitCreateRelationshipContext: vi.fn(),
}));

const { widget } = vi.hoisted(() => ({
  widget: (name: string) => ({ default: () => <div data-widget={name} /> }),
}));
vi.mock('./IncidentDetails', () => widget('details'));
vi.mock('../../common/stix_domain_objects/StixDomainObjectOverview', () => widget('basicInformation'));
vi.mock('../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships', () => widget('latestCreatedRelationships'));
vi.mock('../../common/containers/StixCoreObjectOrStixRelationshipLastContainers', () => widget('latestContainers'));
vi.mock('../../analyses/external_references/StixCoreObjectExternalReferences', () => widget('externalReferences'));
vi.mock('../../common/stix_core_objects/StixCoreObjectLatestHistory', () => widget('mostRecentHistory'));
vi.mock('../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes', () => widget('notes'));
vi.mock('../../common/timeline/ContainerTimelineStrip', () => ({
  default: ({ containerId, basePath }: { containerId: string; basePath: string }) => (
    <div data-widget="timeline" data-container-id={containerId} data-base-path={basePath} />
  ),
}));

const DEFAULT_LAYOUT = [
  { key: 'timeline', width: 12, label: 'Timeline' },
  { key: 'details', width: 6, label: 'Entity details' },
  { key: 'basicInformation', width: 6, label: 'Basic information' },
  { key: 'latestCreatedRelationships', width: 6, label: 'Latest created relationships' },
  { key: 'latestContainers', width: 6, label: 'Latest containers' },
  { key: 'externalReferences', width: 6, label: 'External references' },
  { key: 'mostRecentHistory', width: 6, label: 'Most recent history' },
  { key: 'notes', width: 12, label: 'Notes about this entity' },
];

const incident = { id: 'incident-id', entity_type: 'Incident', objectMarking: [] } as unknown as Incident_incident$key;

const renderOverview = (layout: typeof DEFAULT_LAYOUT) => testRender(<Incident incidentData={incident} />, {
  userContext: createMockUserContext({
    entitySettings: { edges: [{ node: { target_type: 'Incident', overview_layout_customization: layout } }] },
  }),
});

const renderedWidgets = (container: HTMLElement) => Array.from(container.querySelectorAll('[data-widget]')).map((element) => element.getAttribute('data-widget'));

describe('Incident overview', () => {
  it('renders the timeline as the first widget of the default layout', () => {
    const { container } = renderOverview(DEFAULT_LAYOUT);
    expect(renderedWidgets(container)).toEqual(DEFAULT_LAYOUT.map(({ key }) => key));
    const strip = container.querySelector('[data-widget="timeline"]');
    expect(strip).toHaveAttribute('data-container-id', 'incident-id');
    expect(strip).toHaveAttribute('data-base-path', '/dashboard/events/incidents/incident-id');
  });

  it('renders the timeline where the overview layout places it', () => {
    const moved = [...DEFAULT_LAYOUT.slice(1, 3), { ...DEFAULT_LAYOUT[0], width: 6 }, ...DEFAULT_LAYOUT.slice(3)];
    const { container } = renderOverview(moved);
    expect(renderedWidgets(container)).toEqual(moved.map(({ key }) => key));
  });

  it('does not render the timeline when it is hidden in the overview layout', () => {
    const hidden = [{ ...DEFAULT_LAYOUT[0], width: 0 }, ...DEFAULT_LAYOUT.slice(1)];
    const { container } = renderOverview(hidden);
    expect(renderedWidgets(container)).toEqual(DEFAULT_LAYOUT.slice(1).map(({ key }) => key));
  });
});
