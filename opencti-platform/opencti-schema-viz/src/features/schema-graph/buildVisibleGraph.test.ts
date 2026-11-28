import { describe, expect, it } from 'vitest';
import { EMPTY_SNAPSHOT } from '../../state/canvasSnapshot';
import { buildFixtureSchema } from '../../test/fixtures';
import { findShortestPath } from '../find-path/findShortestPath';
import { buildVisibleGraph, type GraphScope, type GroupGraphNode, type RelationGraphEdge } from './buildVisibleGraph';
import { revealKey, typeNodeId } from './graphIds';

const schema = buildFixtureSchema();

const scope = (overrides: Partial<GraphScope>): GraphScope => ({ ...EMPTY_SNAPSHOT, showRelations: false, path: null, ...overrides });

const typeIdsOf = (graph: ReturnType<typeof buildVisibleGraph>) => graph.nodes.flatMap((node) => (node.kind === 'type' ? [node.typeId] : [])).sort();
const relationEdges = (graph: ReturnType<typeof buildVisibleGraph>) => graph.edges.filter((edge): edge is RelationGraphEdge => edge.kind === 'relation');

describe('buildVisibleGraph', () => {
  it('shows pinned types only, without edges, by default', () => {
    const graph = buildVisibleGraph(schema, scope({ pinnedTypeIds: ['Malware', 'Tool'] }));
    expect(typeIdsOf(graph)).toEqual(['Malware', 'Tool']);
    expect(graph.edges).toEqual([]);
  });

  it('connects visible types with merged relation edges', () => {
    const graph = buildVisibleGraph(schema, scope({ pinnedTypeIds: ['Malware', 'Tool', 'Threat-Actor-Group'], showRelations: true }));
    const edge = relationEdges(graph).find((candidate) => candidate.source === typeNodeId('Malware') && candidate.target === typeNodeId('Threat-Actor-Group'));
    expect(edge?.relations.map((relation) => relation.name)).toEqual(['targets']);
    expect(relationEdges(graph).some((candidate) => candidate.source === candidate.target)).toBe(false);
    const expanded = buildVisibleGraph(schema, scope({ pinnedTypeIds: ['Malware'], expandedTypeIds: ['Malware'] }));
    expect(relationEdges(expanded).some((candidate) => candidate.source === typeNodeId('Malware') && candidate.target === typeNodeId('Malware'))).toBe(true);
  });

  it('leaves generic relations out when connecting visible types', () => {
    const names = (overrides: Partial<GraphScope>) => relationEdges(buildVisibleGraph(schema, scope({ pinnedTypeIds: ['Tool', 'Malware'], ...overrides })))
      .flatMap((edge) => edge.relations.map((relation) => relation.name));
    expect(names({ showRelations: true })).not.toContain('related-to');
    expect(names({ expandedTypeIds: ['Tool'] })).toContain('related-to');
  });

  it('draws a relation to an abstract target onto its visible descendants', () => {
    const graph = buildVisibleGraph(schema, scope({ pinnedTypeIds: ['Tool', 'Threat-Actor-Group'], showRelations: true }));
    const edge = relationEdges(graph).find((candidate) => candidate.source === typeNodeId('Tool'));
    expect(edge?.target).toBe(typeNodeId('Threat-Actor-Group'));
    expect(edge?.relations).toEqual([expect.objectContaining({ name: 'attributed-to', viaTypeId: 'Threat-Actor' })]);
  });

  it('expands small relations as neighbors and folds large ones into a target group', () => {
    const graph = buildVisibleGraph(schema, scope({ pinnedTypeIds: ['Malware'], expandedTypeIds: ['Malware'] }));
    const neighbors = graph.nodes.filter((node) => node.kind === 'type' && node.role === 'neighbor').map((node) => node.kind === 'type' && node.typeId);
    expect(neighbors).toContain('Tool');
    expect(neighbors).toContain('Threat-Actor-Group');

    const group = graph.nodes.find((node): node is GroupGraphNode => node.kind === 'group');
    expect(group).toMatchObject({ anchorTypeId: 'Malware', direction: 'out', relationName: 'targets' });
    // Threat-Actor-Group is already on the canvas through `uses` (incoming), so it gets a direct edge instead.
    expect(group?.typeIds).toEqual(['City', 'Country', 'Region', 'Sector']);
    expect(relationEdges(graph).some((edge) => edge.target === typeNodeId('Threat-Actor-Group') && edge.relations.some((relation) => relation.name === 'targets'))).toBe(true);
  });

  it('skips ref attributes unless asked, but always draws an explicitly revealed relation', () => {
    const base = scope({ pinnedTypeIds: ['Malware', 'Threat-Actor-Group'], showRelations: true });
    const names = (graph: ReturnType<typeof buildVisibleGraph>) => relationEdges(graph).flatMap((edge) => edge.relations.map((relation) => relation.name));
    expect(names(buildVisibleGraph(schema, base))).not.toContain('createdBy');
    expect(names(buildVisibleGraph(schema, { ...base, includeRefs: true }))).toContain('createdBy');
    expect(names(buildVisibleGraph(schema, { ...base, showRelations: false, revealedRelations: [revealKey('out', 'Malware', 'Malware_createdBy')] }))).toEqual(['createdBy']);
  });

  it('hides disabled categories but keeps abstract roots', () => {
    const graph = buildVisibleGraph(schema, scope({
      pinnedTypeIds: ['Malware', 'uses', 'Stix-Domain-Object'],
      enabledCategories: { ...EMPTY_SNAPSHOT.enabledCategories, SRO: false },
    }));
    expect(typeIdsOf(graph)).toEqual(['Malware', 'Stix-Domain-Object']);
  });

  it('links each type to its nearest visible ancestor', () => {
    const graph = buildVisibleGraph(schema, scope({ pinnedTypeIds: ['Stix-Domain-Object', 'Threat-Actor-Group'], showInheritance: true }));
    expect(graph.edges).toEqual([
      expect.objectContaining({ kind: 'inheritance', source: typeNodeId('Stix-Domain-Object'), target: typeNodeId('Threat-Actor-Group'), indirect: true }),
    ]);
  });

  it('shows only the path when one is active', () => {
    const path = findShortestPath(schema, 'Sector', 'Tool');
    expect(path).not.toBeNull();
    const graph = buildVisibleGraph(schema, scope({ pinnedTypeIds: ['City'], path }));
    expect(typeIdsOf(graph)).toEqual(['Malware', 'Sector', 'Tool']);
    expect(relationEdges(graph).map((edge) => [edge.source, edge.target])).toEqual([
      [typeNodeId('Malware'), typeNodeId('Sector')],
      [typeNodeId('Malware'), typeNodeId('Tool')],
    ]);
  });
});
