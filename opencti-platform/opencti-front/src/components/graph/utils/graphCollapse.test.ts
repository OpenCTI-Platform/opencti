import { describe, expect, it } from 'vitest';
import { createCollapseCache, GROUP_NODE_PREFIX, isCollapsedMember, isGroupNode, withCollapsedGroups } from './graphCollapse';
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

  it('redraws the links towards the group once and drops the links inside it', () => {
    const result = withCollapsedGroups(data, ['Malware'], label, createCollapseCache());
    const groupLinks = result.links.slice(data.links.length);
    expect(groupLinks).toHaveLength(1);
    expect(groupLinks[0]).toMatchObject({ source: 'actor', target: `${GROUP_NODE_PREFIX}Malware`, relationship_type: 'uses' });
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

  it('tells the members hidden behind a group', () => {
    expect(isCollapsedMember(m1, ['Malware'])).toBe(true);
    expect(isCollapsedMember(actor, ['Malware'])).toBe(false);
    expect(isCollapsedMember(graphNode({ entity_type: 'Malware', relationship_type: 'uses' }), ['Malware'])).toBe(false);
  });
});
