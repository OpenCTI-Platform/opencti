import { describe, expect, it } from 'vitest';
import {
  createCollapseCache,
  drawnTypes,
  GROUP_NODE_PREFIX,
  isCollapsedMember,
  isGroupLink,
  isGroupNode,
  relationshipTotal,
  selectableTypes,
  withCollapsedGroups,
} from './graphCollapse';
import { graphLink, graphNode } from '../../../utils/tests/graphTestData';

const actor = graphNode({ id: 'actor', entity_type: 'Intrusion-Set', x: 0, y: 0 });
const m1 = graphNode({ id: 'm1', entity_type: 'Malware', x: 10, y: 0 });
const m2 = graphNode({ id: 'm2', entity_type: 'Malware', x: 30, y: 20 });
const data = {
  nodes: [actor, m1, m2],
  links: [graphLink(actor, m1), graphLink(actor, m2), graphLink(m1, m2, { relationship_type: 'variant-of', entity_type: 'variant-of' })],
};
const label = (type: string, count: number) => `${count} ${type}`;

describe('withCollapsedGroups', () => {
  it('returns the data untouched without collapsed types', () => {
    expect(withCollapsedGroups(data, [], label, createCollapseCache())).toBe(data);
  });

  it('adds one group node at the centre of its members, keeping the members in the data', () => {
    const result = withCollapsedGroups(data, ['Malware'], label, createCollapseCache());
    const group = result.nodes.find(isGroupNode);
    expect(group?.id).toBe(`${GROUP_NODE_PREFIX}Malware`);
    expect(group?.label).toBe('2 Malware');
    expect(group?.groupOf?.memberIds).toEqual(['m1', 'm2']);
    expect(group?.x).toBe(20);
    expect(group?.y).toBe(10);
    expect(result.nodes).toHaveLength(4);
  });

  it('draws a group link uncertain only when every relationship it stands for is, whatever their order', () => {
    const asserted = graphLink(actor, m1, { inferred: false, confidence: 80 });
    const inferred = graphLink(actor, m2, { inferred: true, confidence: 10 });
    [[asserted, inferred], [inferred, asserted]].forEach((links) => {
      const group = withCollapsedGroups({ nodes: [actor, m1, m2], links }, ['Malware'], label, createCollapseCache()).links.find(isGroupLink);
      expect(group?.inferred).toBe(false);
      expect(group?.confidence).toBe(80);
    });
    const allInferred = [graphLink(actor, m1, { inferred: true, confidence: 10 }), graphLink(actor, m2, { inferred: true, confidence: 20 })];
    const group = withCollapsedGroups({ nodes: [actor, m1, m2], links: allInferred }, ['Malware'], label, createCollapseCache()).links.find(isGroupLink);
    expect(group?.inferred).toBe(true);
    expect(group?.confidence).toBe(20);
  });

  it('never takes the restricted outline of its first member, whatever the order of the members', () => {
    const restricted = graphNode({ id: 'm0', entity_type: 'Malware', x: 0, y: 0, isRestricted: true });
    const first = withCollapsedGroups({ nodes: [restricted, m1, m2], links: [] }, ['Malware'], label, createCollapseCache());
    const last = withCollapsedGroups({ nodes: [m1, m2, restricted], links: [] }, ['Malware'], label, createCollapseCache());
    expect(first.nodes.find(isGroupNode)?.isRestricted).toBe(false);
    expect(last.nodes.find(isGroupNode)?.isRestricted).toBe(false);
  });

  it('redraws the links towards the group once, a link between two members as a loop on the group', () => {
    const result = withCollapsedGroups(data, ['Malware'], label, createCollapseCache());
    const groupLinks = result.links.slice(data.links.length);
    expect(groupLinks).toHaveLength(2);
    expect(groupLinks[0]).toMatchObject({ source_id: 'actor', target_id: `${GROUP_NODE_PREFIX}Malware`, relationship_type: 'uses', represents: 2 });
    expect(groupLinks[1]).toMatchObject({ source_id: `${GROUP_NODE_PREFIX}Malware`, target_id: `${GROUP_NODE_PREFIX}Malware`, relationship_type: 'variant-of', represents: 1 });
  });

  it('counts the relationships a group link stands for, afresh at every computation', () => {
    const cache = createCollapseCache();
    expect(withCollapsedGroups(data, ['Malware'], label, cache).links.find(isGroupLink)?.represents).toBe(2);
    const fewer = { nodes: data.nodes, links: [graphLink(actor, m1)] };
    expect(withCollapsedGroups(fewer, ['Malware'], label, cache).links.find(isGroupLink)?.represents).toBe(1);
  });

  it('totals the relationships drawn as the legend counts them', () => {
    const result = withCollapsedGroups(data, ['Malware'], label, createCollapseCache());
    const drawnNodes = result.nodes.filter((node) => !isCollapsedMember(node, ['Malware']));
    const drawnLinks = result.links.filter(isGroupLink);
    const nested = graphNode({ id: 'nested', entity_type: 'uses', relationship_type: 'uses' });
    const connector = graphLink(actor, nested, { id: 'nested', label: '' });
    // Two `uses` drawn as one link towards the group, the `variant-of` between two members drawn as a loop on it, one
    // nested relationship, its connector not counted.
    expect(relationshipTotal([...drawnNodes, nested], [...drawnLinks, connector])).toBe(4);
  });

  it('lists the types drawn as the legend does, leaving out a type whose entities are all hidden', () => {
    const nested = graphNode({ id: 'nested', entity_type: 'uses', relationship_type: 'uses' });
    const result = withCollapsedGroups(data, ['Malware'], label, createCollapseCache());
    const drawnNodes = [...result.nodes.filter((node) => !isCollapsedMember(node, ['Malware'])), nested];
    const drawnLinks = result.links.filter(isGroupLink);
    // The inventories of the graph also hold an organization, hidden, and its `targets` relationship.
    expect(drawnTypes(drawnNodes, drawnLinks, ['Intrusion-Set', 'Malware', 'Organization', 'uses'], ['targets', 'uses'])).toEqual({
      entityTypes: ['Intrusion-Set', 'Malware'],
      relationshipTypes: ['uses'],
    });
  });

  it('tells the links drawn towards a group from the relationships of the platform', () => {
    const result = withCollapsedGroups(data, ['Malware'], label, createCollapseCache());
    expect(result.links.filter(isGroupLink)).toHaveLength(2);
    expect(data.links.some(isGroupLink)).toBe(false);
  });

  it('leaves hidden entities out of the groups and out of the links redrawn towards them', () => {
    const hidden = graphNode({ id: 'm3', entity_type: 'Malware', x: 50, y: 0 });
    const victim = graphNode({ id: 'victim', entity_type: 'Organization', x: 60, y: 0 });
    const withHidden = { nodes: [...data.nodes, hidden, victim], links: [...data.links, graphLink(hidden, victim, { relationship_type: 'targets', entity_type: 'targets' })] };
    const result = withCollapsedGroups(withHidden, ['Malware'], label, createCollapseCache(), new Set(['m3']));
    const group = result.nodes.find(isGroupNode);
    expect(group?.label).toBe('2 Malware');
    expect(group?.groupOf?.memberIds).toEqual(['m1', 'm2']);
    // The `uses` of the actor and the loop of the `variant-of` between the two members drawn; nothing towards the victim.
    expect(result.links.slice(withHidden.links.length).map((link) => link.target_id)).toEqual([`${GROUP_NODE_PREFIX}Malware`, `${GROUP_NODE_PREFIX}Malware`]);
    // Every member hidden: no group at all.
    expect(withCollapsedGroups(withHidden, ['Malware'], label, createCollapseCache(), new Set(['m1', 'm2', 'm3'])).nodes.some(isGroupNode)).toBe(false);
  });

  it('fades a group link only when every link it stands for is faded', () => {
    const faded = graphLink(actor, m1, { disabled: true });
    const kept = graphLink(actor, m2, { disabled: false });
    const groupLink = (links: typeof data.links) => withCollapsedGroups({ nodes: data.nodes, links }, ['Malware'], label, createCollapseCache()).links.slice(links.length)[0];
    expect(groupLink([faded, kept]).disabled).toBe(false);
    expect(groupLink([kept, faded]).disabled).toBe(false);
    expect(groupLink([faded, graphLink(actor, m2, { disabled: true })]).disabled).toBe(true);
  });

  it('keeps the place of a group node from one computation to the next', () => {
    const cache = createCollapseCache();
    const first = withCollapsedGroups(data, ['Malware'], label, cache).nodes.find(isGroupNode);
    if (first) {
      first.x = 500;
      first.y = 600;
    }
    const second = withCollapsedGroups({ ...data }, ['Malware'], label, cache).nodes.find(isGroupNode);
    expect(second?.x).toBe(500);
    expect(second?.y).toBe(600);
  });

  it('keeps a group link from one computation to the next, pointed at the group node of the latest one', () => {
    const cache = createCollapseCache();
    const first = withCollapsedGroups(data, ['Malware'], label, cache);
    const second = withCollapsedGroups({ ...data }, ['Malware'], label, cache);
    const firstLink = first.links.find(isGroupLink);
    const secondLink = second.links.find(isGroupLink);
    expect(secondLink).toBe(firstLink);
    expect(secondLink?.target).toBe(second.nodes.find(isGroupNode));
    expect(secondLink?.source).toBe(actor);
  });

  it('tells the members hidden behind a group', () => {
    expect(isCollapsedMember(m1, ['Malware'])).toBe(true);
    expect(isCollapsedMember(actor, ['Malware'])).toBe(false);
    expect(isCollapsedMember(graphNode({ entity_type: 'Malware', relationship_type: 'uses' }), ['Malware'])).toBe(false);
  });

  it('offers to select by type only the types that still have a node to pick', () => {
    const inventory = ['Intrusion-Set', 'Malware'];
    expect(selectableTypes(inventory, [actor, m1, m2], () => true)).toEqual(inventory);
    expect(selectableTypes(inventory, [actor, m1, m2], (node) => !isCollapsedMember(node, ['Malware']))).toEqual(['Intrusion-Set']);
    expect(selectableTypes(inventory, [actor, m1, m2], (node) => node.id === 'm2')).toEqual(['Malware']);
  });

  it('never offers the type of a nested relationship drawn as a node', () => {
    const nested = graphNode({ id: 'nested', entity_type: 'uses', relationship_type: 'uses' });
    expect(selectableTypes(['Intrusion-Set', 'uses'], [actor, nested], () => true)).toEqual(['Intrusion-Set']);
  });
});
