import React from 'react';
import { describe, it, expect } from 'vitest';
import { renderHook } from '@testing-library/react';
import { IntlProvider } from 'react-intl';
import useGraphParser, { ObjectToParse } from './useGraphParser';
import type { GraphNode, GraphLink, OctiGraphPositions } from '../graph.types';

/**
 * Helper to build a minimal ObjectToParse for tests.
 */
const constructEntity = (overrides: Partial<ObjectToParse> = {}): ObjectToParse => ({
  id: overrides.id ?? 'entity-1',
  entity_type: overrides.entity_type ?? 'Malware',
  relationship_type: overrides.relationship_type ?? '',
  parent_types: overrides.parent_types ?? ['Stix-Domain-Object'],
  is_inferred: false,
  created: '2025-01-01T00:00:00.000Z',
  start_time: '',
  stop_time: '',
  first_seen: '',
  last_seen: '',
  createdBy: { id: 'author-1', name: 'Author' },
  objectMarking: [],
  ...overrides,
});

const constructRelationship = (overrides: Partial<ObjectToParse> = {}): ObjectToParse => constructEntity({
  entity_type: 'uses',
  relationship_type: 'uses',
  parent_types: ['basic-relationship', 'stix-core-relationship'],
  from: { id: 'entity-A', entity_type: 'Malware' },
  to: { id: 'entity-B', entity_type: 'Attack-Pattern' },
  ...overrides,
});

const emptyPositions: OctiGraphPositions = {};

describe('useGraphParser', () => {
  const getParser = () => {
    const wrapper = ({ children }: { children: React.ReactNode }) => (
      React.createElement(IntlProvider, { locale: 'en', messages: {}, onError: () => {} }, children)
    );
    const { result } = renderHook(() => useGraphParser(), { wrapper });
    return result.current;
  };

  describe('buildGraphDataAfterRelationshipLinkToNodeConversion', () => {
    it('should return previous graph data when relObj has no relationship_type', () => {
      const parser = getParser();
      const previousGraphData = { nodes: [] as GraphNode[], links: [] as GraphLink[] };

      const result = parser.buildGraphDataAfterRelationshipLinkToNodeConversion(
        previousGraphData,
        [],
        emptyPositions,
        { id: 'rel-1', entity_type: 'Malware' }, // no relationship_type
      );

      expect(result).toBe(previousGraphData);
    });

    it('should return previous graph data when relObj is already a node', () => {
      const parser = getParser();
      const existingNode = parser.buildNode(constructEntity({ id: 'rel-1' }), emptyPositions);
      const previousGraphData = { nodes: [existingNode], links: [] as GraphLink[] };

      const result = parser.buildGraphDataAfterRelationshipLinkToNodeConversion(
        previousGraphData,
        [],
        emptyPositions,
        { id: 'rel-1', relationship_type: 'uses', entity_type: 'uses' },
      );

      expect(result).toBe(previousGraphData);
    });

    it('should convert a relationship link to a node', () => {
      const parser = getParser();

      const entityA = constructEntity({ id: 'entity-A', entity_type: 'Malware' });
      const entityB = constructEntity({ id: 'entity-B', entity_type: 'Attack-Pattern' });
      const rel = constructRelationship({ id: 'rel-1', relationship_type: 'related-to' });

      // Build initial graph: two entity nodes + one relationship link
      const nodeA = parser.buildNode(entityA, emptyPositions);
      const nodeB = parser.buildNode(entityB, emptyPositions);
      const relLink = parser.buildLink(rel);

      const previousGraphData = {
        nodes: [nodeA, nodeB],
        links: [relLink],
      };

      const rawObjects = [entityA, entityB, rel];

      const result = parser.buildGraphDataAfterRelationshipLinkToNodeConversion(
        previousGraphData,
        rawObjects,
        emptyPositions,
        { id: 'rel-1', relationship_type: 'uses', entity_type: 'uses' },
      );

      // The relationship should now be a node
      expect(result!.nodes).toHaveLength(3); // entityA + entityB + rel-1 as node
      expect(result!.nodes.map((n) => n.id)).toContain('rel-1');

      // The original link should be removed, replaced by two connector links
      expect(result!.links).toHaveLength(2);
      // One link should go to rel-1, the other from rel-1
      const linkToRel = result!.links.find((l) => l.target_id === 'rel-1');
      const linkFromRel = result!.links.find((l) => l.source_id === 'rel-1');
      expect(linkToRel).toBeDefined();
      expect(linkFromRel).toBeDefined();
      expect(linkToRel!.source_id).toBe('entity-A');
      expect(linkFromRel!.target_id).toBe('entity-B');
    });

    it('should preserve existing nodes and other links', () => {
      const parser = getParser();

      const entityA = constructEntity({ id: 'entity-A' });
      const entityB = constructEntity({ id: 'entity-B' });
      const entityC = constructEntity({ id: 'entity-C' });
      const rel1 = constructRelationship({ id: 'rel-1', from: { id: 'entity-A' }, to: { id: 'entity-B' } });
      const rel2 = constructRelationship({ id: 'rel-2', from: { id: 'entity-B' }, to: { id: 'entity-C' } });

      const nodeA = parser.buildNode(entityA, emptyPositions);
      const nodeB = parser.buildNode(entityB, emptyPositions);
      const nodeC = parser.buildNode(entityC, emptyPositions);
      const link1 = parser.buildLink(rel1);
      const link2 = parser.buildLink(rel2);

      const previousGraphData = {
        nodes: [nodeA, nodeB, nodeC],
        links: [link1, link2],
      };

      const result = parser.buildGraphDataAfterRelationshipLinkToNodeConversion(
        previousGraphData,
        [entityA, entityB, entityC, rel1, rel2],
        emptyPositions,
        { id: 'rel-1', relationship_type: 'uses', entity_type: 'uses' },
      );

      // rel-2 link should still be present
      expect(result!.links.find((l) => l.id === 'rel-2')).toBeDefined();
      // The original direct link for rel-1 (source=entity-A, target=entity-B) should be gone,
      // replaced by two connector links going through the rel-1 node.
      const directRel1Link = result!.links.find(
        (l) => l.id === 'rel-1' && l.source_id === 'entity-A' && l.target_id === 'entity-B',
      );
      expect(directRel1Link).toBeUndefined();
      // All original nodes should be preserved
      expect(result!.nodes.find((n) => n.id === 'entity-A')).toBeDefined();
      expect(result!.nodes.find((n) => n.id === 'entity-B')).toBeDefined();
      expect(result!.nodes.find((n) => n.id === 'entity-C')).toBeDefined();
      // Plus the new relationship node
      expect(result!.nodes.find((n) => n.id === 'rel-1')).toBeDefined();
      expect(result!.nodes).toHaveLength(4);
    });

    it('should return previous graph data when previousGraphData is undefined', () => {
      const parser = getParser();

      const result = parser.buildGraphDataAfterRelationshipLinkToNodeConversion(
        undefined,
        [],
        emptyPositions,
        { id: 'rel-1', relationship_type: 'uses', entity_type: 'uses' },
      );

      expect(result).toBeUndefined();
    });
  });
});
