import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import { graphNode } from '../../../utils/tests/graphTestData';
import { GraphProvider } from '../GraphContext';
import GraphToolbarExpandTools from './GraphToolbarExpandTools';
import GraphToolbarContentTools from './GraphToolbarContentTools';
import useGraphInteractions from '../utils/useGraphInteractions';
import type { ObjectToParse } from '../utils/useGraphParser';

const mocks = vi.hoisted(() => ({ addEntities: vi.fn() }));

// The panel adding entities is tested on its own: only whether it is offered matters here.
vi.mock('@components/workspaces/investigations/InvestigationAddStixCoreObjects', () => ({
  default: () => {
    mocks.addEntities();
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

const malware = graphNode({ id: 'malware', label: 'Emotet' });
const emotet = { id: 'malware', entity_type: 'Malware', name: 'Emotet', parent_types: ['Stix-Domain-Object'] } as unknown as ObjectToParse;
const CHANGES = [
  'Expand the selected entities',
  'Restore the state of the graphic before the last expansion',
  'Remove selected items',
  'Create a relationship',
  'Create a sighting',
  'Create a nested relationship',
];

// Selects the entity so that expanding and removing are possible, but for the access to the investigation.
const SelectEntities = ({ nodes }: { nodes: (typeof malware)[] }) => {
  const { setSelectedNodes } = useGraphInteractions();
  React.useEffect(() => setSelectedNodes(nodes), []);
  return null;
};

const renderTools = (readOnly?: boolean) => testRender(
  <GraphProvider objects={[emotet]} context="investigation" readOnly={readOnly}>
    <SelectEntities nodes={[malware]} />
    <GraphToolbarExpandTools onInvestigationExpand={vi.fn()} onInvestigationRollback={vi.fn()} />
    <GraphToolbarContentTools entity={{ id: 'investigation-1' }} onRemove={vi.fn()} onAddRelation={vi.fn()} />
  </GraphProvider>,
);

describe('Investigation tools of the graph toolbar', () => {
  afterEach(() => {
    sessionStorage.clear();
    mocks.addEntities.mockClear();
  });

  it('hides every tool changing the investigation from a member who cannot change it', () => {
    sessionStorage.setItem('investigation-state-', JSON.stringify([{ type: 'expand', dateTime: 0, objectsIds: ['malware'] }]));
    renderTools(true);

    CHANGES.forEach((name) => {
      expect(screen.queryByRole('button', { name })).not.toBeInTheDocument();
    });
    expect(mocks.addEntities).not.toHaveBeenCalled();
  });

  it('offers the tools to an editor', () => {
    sessionStorage.setItem('investigation-state-', JSON.stringify([{ type: 'expand', dateTime: 0, objectsIds: ['malware'] }]));
    renderTools();

    CHANGES.forEach((name) => {
      expect(screen.getByRole('button', { name })).toBeInTheDocument();
    });
    ['Expand the selected entities', 'Restore the state of the graphic before the last expansion', 'Remove selected items'].forEach((name) => {
      expect(screen.getByRole('button', { name })).not.toHaveAttribute('aria-disabled');
    });
    expect(mocks.addEntities).toHaveBeenCalled();
  });
});
