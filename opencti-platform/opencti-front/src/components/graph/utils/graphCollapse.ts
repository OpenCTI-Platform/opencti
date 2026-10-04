import type { GraphLink, GraphNode, LibGraphProps } from '../graph.types';

type GraphData = NonNullable<LibGraphProps['graphData']>;

export const GROUP_NODE_PREFIX = 'group:';
export const GROUP_LINK_PREFIX = 'group-link:';

export const isGroupNode = (node: Pick<GraphNode, 'groupOf'> | null | undefined) => !!node?.groupOf;

/**
 * A link drawn towards a group node: it stands for every relationship between the group's members
 * and one entity, so it is no object of the platform and is never selected or acted on.
 */
export const isGroupLink = (link: Pick<GraphLink, 'id'> | null | undefined) => !!link?.id?.startsWith(GROUP_LINK_PREFIX);

const endpointId = (end: GraphLink['source']) => (typeof end === 'object' && end !== null ? end.id : end);

/**
 * Objects kept from one computation to the next, so a group node keeps the place the layout gave
 * it and a group link keeps its identity while the reader collapses and expands other types.
 */
export interface CollapseCache {
  nodes: Map<string, GraphNode>;
  links: Map<string, GraphLink>;
}

export const createCollapseCache = (): CollapseCache => ({ nodes: new Map(), links: new Map() });

/**
 * The drawing data with every collapsed entity type stood for by one group node: the members stay
 * in the data (hidden, so selection, filters and positions keep working on them) and every link
 * touching a member is redrawn once towards the group. Hidden entities are neither members nor
 * linked through a group, as they are not drawn. Without collapsed types the data is returned as is.
 */
export const withCollapsedGroups = (
  data: GraphData,
  collapsedTypes: readonly string[],
  groupLabel: (entityType: string, count: number) => string,
  cache: CollapseCache,
  hiddenIds: ReadonlySet<string> = new Set(),
): GraphData => {
  if (collapsedTypes.length === 0) return data;
  const collapsed = new Set(collapsedTypes);
  const groupOfMember = new Map<string, string>();
  const members = new Map<string, GraphNode[]>();
  data.nodes.forEach((node) => {
    if (!collapsed.has(node.entity_type) || node.relationship_type || hiddenIds.has(node.id)) return;
    const groupId = `${GROUP_NODE_PREFIX}${node.entity_type}`;
    groupOfMember.set(node.id, groupId);
    const list = members.get(groupId);
    if (list) list.push(node);
    else members.set(groupId, [node]);
  });
  if (members.size === 0) return data;

  const groupNodes = [...members.entries()].map(([groupId, list]) => {
    const [first] = list;
    const centre = list.reduce((acc, n) => ({ x: acc.x + (n.x ?? 0) / list.length, y: acc.y + (n.y ?? 0) / list.length }), { x: 0, y: 0 });
    const existing = cache.nodes.get(groupId);
    const node: GraphNode = {
      ...first,
      id: groupId,
      label: groupLabel(first.entity_type, list.length),
      name: groupLabel(first.entity_type, list.length),
      disabled: list.every((member) => member.disabled),
      isNestedInferred: false,
      numberOfConnectedElement: undefined,
      markedBy: [],
      confidence: null,
      raw: undefined,
      groupOf: { entityType: first.entity_type, memberIds: list.map((member) => member.id) },
      x: existing?.x ?? centre.x,
      y: existing?.y ?? centre.y,
      z: 0,
      fx: undefined,
      fy: undefined,
      fz: undefined,
    };
    cache.nodes.set(groupId, node);
    return node;
  });

  // The renderer replaces the ends of a link by their nodes; a group node is a new object at every
  // computation, so a link kept from the cache is pointed at the nodes of this computation.
  const nodeOf = new Map<string, GraphNode>([...data.nodes, ...groupNodes].map((node) => [node.id, node]));
  const groupLinks = new Map<string, GraphLink>();
  data.links.forEach((link) => {
    const sourceId = endpointId(link.source) ?? link.source_id;
    const targetId = endpointId(link.target) ?? link.target_id;
    if (hiddenIds.has(sourceId) || hiddenIds.has(targetId)) return;
    const source = groupOfMember.get(sourceId) ?? sourceId;
    const target = groupOfMember.get(targetId) ?? targetId;
    if (source === sourceId && target === targetId) return;
    if (source === target) return;
    const id = `${GROUP_LINK_PREFIX}${source}|${target}|${link.relationship_type || link.entity_type}`;
    const drawn = groupLinks.get(id);
    if (drawn) {
      // Faded only when every link the group link stands for is faded by the filters.
      drawn.disabled = Boolean(drawn.disabled && link.disabled);
      drawn.represents = (drawn.represents ?? 1) + 1;
      return;
    }
    const existing = cache.links.get(id);
    const fields = { ...link, id, source: nodeOf.get(source) ?? source, target: nodeOf.get(target) ?? target, source_id: source, target_id: target, raw: undefined };
    const groupLink: GraphLink = existing ? Object.assign(existing, fields) : fields;
    groupLink.disabled = link.disabled;
    groupLink.represents = 1;
    cache.links.set(id, groupLink);
    groupLinks.set(id, groupLink);
  });

  return { nodes: [...data.nodes, ...groupNodes], links: [...data.links, ...groupLinks.values()] };
};

/** Whether a member of a collapsed type, hidden behind its group node. */
export const isCollapsedMember = (node: Pick<GraphNode, 'entity_type' | 'relationship_type' | 'groupOf'>, collapsedTypes: readonly string[]) => !node.groupOf
  && !node.relationship_type
  && collapsedTypes.includes(node.entity_type);
