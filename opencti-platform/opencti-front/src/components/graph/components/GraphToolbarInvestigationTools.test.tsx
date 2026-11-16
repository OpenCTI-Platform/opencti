import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import { graphNode } from '../../../utils/tests/graphTestData';
import { GraphProvider } from '../GraphContext';
import GraphToolbarExpandTools from './GraphToolbarExpandTools';
import GraphToolbarContentTools from './GraphToolbarContentTools';
import useGraphInteractions from '../utils/useGraphInteractions';

const mocks = vi.hoisted(() => ({ addEntities: vi.fn() }));

// The panel adding entities is tested on its own: only the reason it receives matters here.
vi.mock('@components/workspaces/investigations/InvestigationAddStixCoreObjects', () => ({
  default: (props: { disabledReason?: string }) => {
    mocks.addEntities(props);
    return null;
  },
}));
vi.mock('../../../private/components/workspaces/investigations/investigations_enrichment/InvestigationEnrichmentTool', () => ({ default: () => null }));
vi.mock('@components/events/stix_sighting_relationships/StixSightingRelationshipCreation', () => ({ default: () => null }));
vi.mock('@components/common/stix_core_relationships/StixCoreRelationshipCreation', () => ({ default: () => null }));
vi.mock('@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipCreation', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipCreation')>()),
  default: () => null,
}));

const VIEW_ONLY = 'You have view access to this investigation';
const malware = graphNode({ id: 'malware', label: 'Emotet' });

// Selects the entity so that expanding and removing are possible, but for the access to the investigation.
const SelectEntities = ({ nodes }: { nodes: (typeof malware)[] }) => {
  const { setSelectedNodes } = useGraphInteractions();
  React.useEffect(() => setSelectedNodes(nodes), []);
  return null;
};

const renderTools = (editDisabledReason?: string, ...selected: (typeof malware)[]) => testRender(
  <GraphProvider objects={[]} context="investigation" editDisabledReason={editDisabledReason}>
    <SelectEntities nodes={selected.length > 0 ? selected : [malware]} />
    <GraphToolbarExpandTools onInvestigationExpand={vi.fn()} onInvestigationRollback={vi.fn()} />
    <GraphToolbarContentTools entity={{ id: 'investigation-1' }} onRemove={vi.fn()} onAddRelation={vi.fn()} />
  </GraphProvider>,
);

describe('Investigation tools of the graph toolbar', () => {
  afterEach(() => {
    sessionStorage.clear();
    mocks.addEntities.mockClear();
  });

  it('disables adding, expanding, rolling back and removing for a view only member, saying why', () => {
    sessionStorage.setItem('investigation-state-', JSON.stringify([{ type: 'expand', dateTime: 0, objectsIds: ['malware'] }]));
    renderTools(VIEW_ONLY);

    ['Expand the selected entities', 'Restore the state of the graphic before the last expansion', 'Remove selected items'].forEach((name) => {
      const tool = screen.getByRole('button', { name });
      expect(tool).toHaveAttribute('aria-disabled', 'true');
      expect(tool).toHaveAccessibleDescription(VIEW_ONLY);
    });
    expect(mocks.addEntities).toHaveBeenLastCalledWith(expect.objectContaining({ disabledReason: VIEW_ONLY }));
  });

  it('leaves the tools to an editor', () => {
    sessionStorage.setItem('investigation-state-', JSON.stringify([{ type: 'expand', dateTime: 0, objectsIds: ['malware'] }]));
    renderTools();

    ['Expand the selected entities', 'Restore the state of the graphic before the last expansion', 'Remove selected items'].forEach((name) => {
      expect(screen.getByRole('button', { name })).not.toHaveAttribute('aria-disabled');
    });
    expect(mocks.addEntities).toHaveBeenLastCalledWith(expect.objectContaining({ disabledReason: undefined }));
  });

  it('still says that inferred knowledge cannot be removed to an editor', () => {
    renderTools(undefined, graphNode({ id: 'inferred', label: 'Inferred', isNestedInferred: true }));

    expect(screen.getByRole('button', { name: 'Remove selected items' })).toHaveAccessibleDescription('Inferred knowledge cannot be removed');
  });

  it('disables creating relationships, sightings and nested relationships for a view only member, saying why', () => {
    renderTools(VIEW_ONLY);

    ['Create a relationship', 'Create a sighting', 'Create a nested relationship'].forEach((name) => {
      const tool = screen.getByRole('button', { name });
      expect(tool).toHaveAttribute('aria-disabled', 'true');
      expect(tool).toHaveAccessibleDescription(VIEW_ONLY);
    });
  });

  it('still asks an editor to select the entities to link', () => {
    renderTools();

    ['Create a relationship', 'Create a sighting', 'Create a nested relationship'].forEach((name) => {
      expect(screen.getByRole('button', { name })).toHaveAccessibleDescription('Select the entities to link first');
    });
  });

  it('lets an editor link two selected entities', () => {
    renderTools(undefined, malware, graphNode({ id: 'intrusion-set', label: 'APT-X', entity_type: 'Intrusion-Set' }));

    ['Create a relationship', 'Create a sighting'].forEach((name) => {
      expect(screen.getByRole('button', { name })).not.toHaveAttribute('aria-disabled');
    });
  });
});
