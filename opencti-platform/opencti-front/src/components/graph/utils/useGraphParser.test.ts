import React from 'react';
import { describe, it, expect, beforeAll } from 'vitest';
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
  let parser: ReturnType<typeof useGraphParser>;

  beforeAll(() => {
    const wrapper = ({ children }: { children: React.ReactNode }) => (
      React.createElement(IntlProvider, { locale: 'en', messages: {}, onError: () => {} }, children)
    );
    const { result } = renderHook(() => useGraphParser(), { wrapper });
    parser = result.current;
  });

  describe('buildNode', () => {
    it('should build a node with correct id and attributes', () => {
      const entity = constructEntity({
        id: 'node-1',
        entity_type: 'Malware',
        createdBy: { id: 'creator-1', name: 'Creator' },
        objectMarking: [{ id: 'marking-1', definition: 'TLP:RED' }],
      });

      const node = parser.buildNode(entity, emptyPositions);

      expect(node.id).toBe('node-1');
      expect(node.entity_type).toBe('Malware');
      expect(node.createdBy).toEqual({ id: 'creator-1', name: 'Creator' });
      expect(node.markedBy).toEqual([{ id: 'marking-1', definition: 'TLP:RED' }]);
      expect(node.isObservable).toBe(false);
      expect(node.isNestedInferred).toBe(false);
      expect(node.disabled).toBe(false);
      expect(node.val).toBe(1);
      expect(node.z).toBe(0); // default z to 0 when no position is provided
    });

    it('should use graph positions when provided', () => {
      const entity = constructEntity({ id: 'node-1' });
      const positions: OctiGraphPositions = {
        'node-1': { id: 'node-1', x: 100, y: 200, z: 300 },
      };

      const node = parser.buildNode(entity, positions);

      expect(node.x).toBe(100);
      expect(node.y).toBe(200);
      expect(node.z).toBe(300);
      expect(node.fx).toBe(100);
      expect(node.fy).toBe(200);
      expect(node.fz).toBe(300);
    });

    it('should use custom color when x_opencti_color is set', () => {
      const entity = constructEntity({ id: 'node-1', x_opencti_color: '#ff0000' });
      const node = parser.buildNode(entity, emptyPositions);
      expect(node.color).toBe('#ff0000');
    });

    it('should use provided numberOfConnectedElement over data value', () => {
      const entity = constructEntity({ id: 'node-1', numberOfConnectedElement: 10 });

      const node = parser.buildNode(entity, emptyPositions, 5);

      expect(node.numberOfConnectedElement).toBe(5);
    });

    it('should fall back to data numberOfConnectedElement when not provided', () => {
      const entity = constructEntity({ id: 'node-1', numberOfConnectedElement: 10 });

      const node = parser.buildNode(entity, emptyPositions);

      expect(node.numberOfConnectedElement).toBe(10);
    });

    it('should set fromId/toId for relationship entities', () => {
      const rel = constructRelationship({ id: 'rel-1' });

      const node = parser.buildNode(rel, emptyPositions);

      expect(node.fromId).toBe('entity-A');
      expect(node.fromType).toBe('Malware');
      expect(node.toId).toBe('entity-B');
      expect(node.toType).toBe('Attack-Pattern');
    });
  });

  describe('buildGraphDataAfterRelationshipLinkToNodeConversion', () => {
    it('should return previous graph data when relObj has no relationship_type', () => {
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
