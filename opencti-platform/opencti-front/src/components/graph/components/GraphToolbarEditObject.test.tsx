import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import { graphql } from 'react-relay';
import testRender from '../../../utils/tests/test-render';
import { graphLink, graphNode } from '../../../utils/tests/graphTestData';
import type { GraphLink, GraphNode } from '../graph.types';
import GraphToolbarEditObject from './GraphToolbarEditObject';

const context = vi.hoisted(() => ({ current: {} as unknown }));
vi.mock('../GraphContext', () => ({ useGraphContext: () => context.current }));
vi.mock('../utils/useGraphInteractions', () => ({ default: () => ({ updateNode: vi.fn(), addLink: vi.fn() }) }));
// The edition forms query the platform when they mount; the graph only decides which one to open.
vi.mock('@components/common/stix_domain_objects/StixDomainObjectEdition', () => ({ default: () => null }));
vi.mock('@components/observations/stix_cyber_observables/StixCyberObservableEdition', () => ({ default: () => null }));
vi.mock('@components/common/stix_core_relationships/StixCoreRelationshipEdition', () => ({ default: () => null }));
vi.mock('@components/events/stix_sighting_relationships/StixSightingRelationshipEdition', () => ({ default: () => null }));
vi.mock('@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipEdition', () => ({ default: () => null }));

const query = {} as ReturnType<typeof graphql>;
const actor = graphNode({ id: 'actor', entity_type: 'Intrusion-Set' });
const malware = graphNode({ id: 'malware' });

const renderEditOf = (selectedNodes: GraphNode[], selectedLinks: GraphLink[]) => {
  context.current = { rawObjects: [], graphState: { selectedNodes, selectedLinks } };
  const { unmount } = testRender(<GraphToolbarEditObject stixCoreObjectRefetchQuery={query} relationshipRefetchQuery={query} />);
  return { edit: screen.getByRole('button', { name: 'Edit the selected item' }), unmount };
};
const renderEdit = (link: GraphLink) => renderEditOf([], [link]);

describe('GraphToolbarEditObject', () => {
  it('edits a selected relationship', () => {
    expect(renderEdit(graphLink(actor, malware)).edit).not.toHaveAttribute('aria-disabled', 'true');
  });

  it('never edits an inferred relationship, directly inferred or nested', () => {
    [{ inferred: true, isNestedInferred: false }, { inferred: false, isNestedInferred: true }].forEach((flags, index) => {
      const { edit, unmount } = renderEdit(graphLink(actor, malware, { id: `inferred-${index}`, ...flags }));
      expect(edit).toHaveAttribute('aria-disabled', 'true');
      expect(edit).toHaveAccessibleDescription('Inferred knowledge cannot be edited');
      unmount();
    });
  });

  it('never edits a directly inferred relationship drawn as a node, the end of a nested relationship', () => {
    const relationship = graphNode({
      id: 'inferred-uses',
      entity_type: 'uses',
      relationship_type: 'uses',
      parent_types: ['basic-relationship', 'stix-relationship', 'stix-core-relationship'],
      isNestedInferred: false,
      raw: { is_inferred: true } as never,
    });
    const { edit } = renderEditOf([relationship], []);
    expect(edit).toHaveAttribute('aria-disabled', 'true');
    expect(edit).toHaveAccessibleDescription('Inferred knowledge cannot be edited');
  });
});
