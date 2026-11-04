import * as R from 'ramda';
import { dateFormat, jsDate } from '../../../utils/Time';
import { isNone, useFormatter } from '../../i18n';
import { defaultDate, getMainRepresentative } from '../../../utils/defaultRepresentatives';
import { OctiGraphPositions, GraphLink, GraphNode, LibGraphProps } from '../graph.types';
import { EMPTY_VALUE, truncate, sanitize } from '../../../utils/String';
import GRAPH_IMAGES from './graphImages';
import { itemColor } from '../../../utils/Colors';

export interface ObjectToParse {
  id: string;
  standard_id?: string;
  entity_type: string;
  relationship_type: string;
  parent_types: string[];
  types?: string[] | null | undefined;
  is_inferred: boolean;
  observable_value?: string;
  observableName?: string;
  x_opencti_color?: string;
  x_opencti_additional_names?: string[];
  hashes?: {
    algorithm: string;
    hash: string;
  }[];
  color?: string;
  numberOfConnectedElement?: number;
  createdBy: {
    id: string;
    name: string;
  };
  confidence?: number | null;
  created: string;
  start_time: string;
  stop_time: string;
  first_seen: string;
  last_seen: string;
  from?: {
    id: string;
    relationship_type?: string;
    entity_type?: string;
  };
  to?: {
    id: string;
    relationship_type?: string;
    entity_type?: string;
  };
  objectMarking: {
    id: string;
    definition: string;
    x_opencti_color?: string | null;
  }[];
  // Other containers associated to this object.
  // Used for correlation graphs.
  linkedContainers?: ObjectToParse[];
}

/**
 * The full name of a node as plain text. `name` is the HTML of the library tooltip and `label`
 * is shortened, so the name is read again from the object received from the query.
 */
export const graphNodeTitle = (node: Pick<GraphNode, 'label' | 'raw' | 'relationship_type' | 'groupOf' | 'isRestricted'>): string => {
  if (node.groupOf || node.relationship_type || node.isRestricted || !node.raw) return node.label;
  return getMainRepresentative(node.raw) || node.label;
};

/** Name the platform gives to an entity the reader may not see; it keeps only its id and types. */
const RESTRICTED_NAME = 'Restricted';

/**
 * Whether the object is the placeholder the platform returns for an entity the reader may not see:
 * every text value replaced by "Restricted", its standard id included, which decides when the query
 * fetched it. Without it: named "Restricted", with every other value emptied (no author, no marking,
 * dates at the start of time); a readable entity that happens to be named "Restricted" keeps its
 * author, its markings or its real dates, and is not taken for one.
 */
export const isRestrictedObject = (data: ObjectToParse) => {
  if (data.parent_types.includes('basic-relationship')) return false;
  if (data.standard_id) return data.standard_id === RESTRICTED_NAME;
  const { name, representative, created_at: createdAt } = data as ObjectToParse & {
    name?: string | null;
    representative?: { main?: string | null } | null;
    created_at?: string | null;
  };
  if (name !== RESTRICTED_NAME && representative?.main !== RESTRICTED_NAME) return false;
  const dates = [data.created, createdAt].filter((date): date is string => !!date);
  return !data.createdBy?.id
    && (data.objectMarking ?? []).length === 0
    && dates.every((date) => new Date(date).getTime() === 0);
};

/** Id of the placeholder marking of unmarked elements, which the marking filter lists as "None". */
export const NO_MARKING_ID = 'abb8eb18-a02c-48e9-adae-08c92275c87e';
/** Id of the placeholder author of elements without one, which the author filter lists as "None". */
export const NO_AUTHOR_ID = '0533fcc9-b9e8-4010-877c-174343cb24cd';

const useGraphParser = () => {
  const { t_i18n } = useFormatter();

  const getRelationshipName = (data: ObjectToParse, forNode = false) => {
    const key = forNode ? data.relationship_type : data.entity_type;
    const relTypeStr = `<strong>${t_i18n(`relationship_${key}`)}</strong>`;
    const createdStr = `${t_i18n('Created the')} ${dateFormat(data.created) ?? '-'}`;
    const start = data.start_time || data.first_seen;
    const startStr = `${t_i18n('Start time')} ${isNone(start) ? EMPTY_VALUE : dateFormat(start)}`;
    const end = data.stop_time || data.last_seen;
    const endStr = `${t_i18n('Stop time')} ${isNone(end) ? EMPTY_VALUE : dateFormat(end)}`;
    return `${relTypeStr}<br/>${createdStr}<br/>${startStr}<br/>${endStr}`;
  };

  const getMarkings = (data: ObjectToParse): GraphNode['markedBy'] => {
    if (data.objectMarking && data.objectMarking.length > 0) {
      return data.objectMarking.map((m) => (m.x_opencti_color
        ? { id: m.id, definition: m.definition, x_opencti_color: m.x_opencti_color }
        : { id: m.id, definition: m.definition }));
    }
    return [{ id: NO_MARKING_ID, definition: t_i18n('None') }];
  };

  const getCreatedBy = (data: ObjectToParse) => {
    return data.createdBy ? data.createdBy : {
      id: NO_AUTHOR_ID,
      name: t_i18n('None'),
    };
  };

  const getIsNestedInferred = (data: ObjectToParse) => {
    return (data.types?.includes('inferred') && !data.types.includes('manual')) || false;
  };

  const getNodeLabel = (data: ObjectToParse) => {
    if (data.parent_types.includes('basic-relationship')) {
      return t_i18n(`relationship_${data.relationship_type}`);
    }
    if (data.entity_type === 'StixFile' && data.observable_value) {
      return truncate(data.observable_value, 20);
    }
    return truncate(
      getMainRepresentative(data),
      data.entity_type === 'Attack-Pattern' ? 30 : 20,
    );
  };

  const getNodeImg = (data: ObjectToParse) => {
    const key = data.parent_types.includes('basic-relationship')
      ? 'relationship'
      : data.entity_type;
    return GRAPH_IMAGES[key] || GRAPH_IMAGES.Unknown;
  };

  const getNodeName = (data: ObjectToParse) => {
    if (data.relationship_type) {
      return getRelationshipName(data, true);
    }
    if (data.entity_type === 'StixFile' && data.observable_value) {
      const hashAlgorithms = ['SHA-512', 'SHA-256', 'SHA-1', 'MD5'];
      // Find if the observable_value matches one of the hashes
      let displayValue = data.observable_value;
      let label = 'Name';
      const matchingHash = (data.hashes ?? []).find((hashObj) => {
        return hashObj.hash === data.observable_value && hashAlgorithms.includes(hashObj.algorithm);
      });
      if (matchingHash) {
        displayValue = matchingHash.hash;
        label = `${matchingHash.algorithm}`;
      } else if (data.observable_value === data.observableName) {
        // Find if observable_value matches observableName
        displayValue = data.observable_value;
        label = 'Name';
      }
      // List of other hashes to display (without duplicating the observable_value)
      const hashesList = data.hashes && Array.isArray(data.hashes)
        ? data.hashes
            .filter((hashObj) => hashObj.hash !== displayValue)
            .map((hashObj) => `${hashObj.algorithm}: ${hashObj.hash}`)
            .join('\n')
        : '';
      // Add name (observableName) if available and different from observable_value
      const additionalInfo = (data.observableName && data.observableName !== displayValue) ? `\nName: ${data.observableName}` : '';
      // Add additional_names if available and different from `observableName`.
      const additionalNames = data.x_opencti_additional_names && Array.isArray(data.x_opencti_additional_names)
        ? data.x_opencti_additional_names
            .filter((additionalName) => additionalName !== data.observableName)
            .join(', ')
        : '';
      const additionalNamesString = additionalNames ? `\n${t_i18n('Additional Names')}: ${additionalNames}` : '';
      return `${label}: ${displayValue}${hashesList ? `\n${hashesList}` : ''}${additionalInfo}${additionalNamesString}\n${dateFormat(defaultDate(data))}`;
    }
    return `${getMainRepresentative(data)}\n${dateFormat(defaultDate(data))}`;
  };

  const buildNode = (
    data: ObjectToParse,
    graphPositions: OctiGraphPositions,
    numberOfConnectedElement?: number,
  ): GraphNode => {
    const isRestricted = isRestrictedObject(data);
    return {
      id: data.id,
      disabled: false,
      val: 1,
      fx: graphPositions[data.id] && graphPositions[data.id].x,
      fy: graphPositions[data.id] && graphPositions[data.id].y,
      fz: graphPositions[data.id] && graphPositions[data.id].z,
      x: graphPositions[data.id] && graphPositions[data.id].x,
      y: graphPositions[data.id] && graphPositions[data.id].y,
      z: (graphPositions[data.id] && graphPositions[data.id].z) ?? 0,
      color: data.x_opencti_color || data.color || itemColor(data.entity_type, false),
      parent_types: data.parent_types,
      entity_type: data.entity_type,
      relationship_type: data.relationship_type,
      fromId: data.from?.id,
      fromType: data.from?.entity_type,
      toId: data.to?.id,
      toType: data.to?.entity_type,
      isObservable: !!data.observable_value,
      numberOfConnectedElement: numberOfConnectedElement ?? data.numberOfConnectedElement,
      ...getNodeImg(data),
      name: sanitize(getNodeName(data), true),
      label: isRestricted ? t_i18n('Restricted') : (getNodeLabel(data) || t_i18n(`entity_${data.entity_type}`)),
      isRestricted,
      markedBy: getMarkings(data),
      createdBy: getCreatedBy(data),
      defaultDate: jsDate(defaultDate(data)),
      isNestedInferred: getIsNestedInferred(data),
      confidence: data.confidence ?? null,
      raw: data,
    };
  };

  const buildLink = (data: ObjectToParse, override?: Partial<GraphLink>): GraphLink => {
    const baseLink = {
      id: data.id,
      disabled: false,
      target: data.to?.id ?? '',
      target_id: data.to?.id ?? '',
      source: data.from?.id ?? '',
      source_id: data.from?.id ?? '',
      inferred: data.is_inferred,
      entity_type: data.entity_type,
      parent_types: data.parent_types,
      relationship_type: data.relationship_type,
      label: t_i18n(`relationship_${data.entity_type}`),
      markedBy: getMarkings(data),
      name: sanitize(getRelationshipName(data), false),
      createdBy: getCreatedBy(data),
      defaultDate: jsDate(defaultDate(data)),
      isNestedInferred: getIsNestedInferred(data),
      confidence: data.confidence ?? null,
      raw: data,
    };
    return {
      ...baseLink,
      ...(override ?? {}),
    };
  };

  /**
   * Check if a relationship is nested, i.e. its from or to is itself a relationship.
   */
  const isNestedRelationship = (data: ObjectToParse): boolean => {
    return !!(data.from && data.to && (data.from.relationship_type || data.to.relationship_type));
  };

  /**
   * Build the two connector links for a nested relationship displayed as a node:
   * one from its source to the relationship node, one from the relationship node to its target.
   */
  const buildNestedLinks = (data: ObjectToParse): [GraphLink, GraphLink] => {
    return [
      buildLink(data, { name: '', label: '', target: data.id, target_id: data.id }),
      buildLink(data, { name: '', label: '', source: data.id, source_id: data.id }),
    ];
  };

  const buildGraphData = (objects: ObjectToParse[], graphPositions: OctiGraphPositions) => {
    const uniqObjects = R.uniqBy(R.prop('id'), objects);
    const uniqIds = uniqObjects.map((o) => o.id);
    const relationshipsIdsInNestedRelationship = objects.flatMap((o) => {
      if (!isNestedRelationship(o)) return [];
      const ids: string[] = [];
      if (o.from?.relationship_type) ids.push(o.from.id);
      if (o.to?.relationship_type) ids.push(o.to.id);
      return ids;
    });

    const links = uniqObjects.flatMap((o) => {
      if (!o.from || !o.to) return [];
      if (!uniqIds.includes(o.from.id)) return [];
      if (!uniqIds.includes(o.to.id)) return [];
      if (
        o.parent_types.includes('basic-relationship')
        && !relationshipsIdsInNestedRelationship.includes(o.id)
      ) {
        return buildLink(o);
      }
      if (relationshipsIdsInNestedRelationship.includes(o.id)) {
        return buildNestedLinks(o);
      }
      return [];
    });

    // Map to know how many links are displayed for each node
    const nodesLinksCounter = new Map<string, number>();
    links.forEach((link) => {
      const from = link.source_id;
      const to = link.target_id;
      nodesLinksCounter.set(from, (nodesLinksCounter.get(from) ?? 0) + 1);
      nodesLinksCounter.set(to, (nodesLinksCounter.get(to) ?? 0) + 1);
    });

    const nodes = uniqObjects.flatMap((o) => {
      if (
        o.parent_types.includes('basic-relationship')
        && !relationshipsIdsInNestedRelationship.includes(o.id)
      ) {
        return [];
      }
      let numberOfConnectedElement;
      if (o.numberOfConnectedElement !== undefined) {
        // The diff between all connections less the ones displayed in the graph.
        numberOfConnectedElement = o.numberOfConnectedElement - (nodesLinksCounter.get(o.id) ?? 0);
      } else if (
        !o.parent_types.includes('Stix-Meta-Object')
        && !o.parent_types.includes('Identity')
      ) {
        // Keep undefined for Meta and Identity objects to display a '?' while the query
        // to fetch real count is loading.
        numberOfConnectedElement = 0;
      }
      return buildNode(o, graphPositions, numberOfConnectedElement);
    });

    return {
      nodes,
      links,
    };
  };

  const buildCorrelationData = (objects: ObjectToParse[], graphPositions: OctiGraphPositions) => {
    // Need to be > 1 because 1 means self container.
    const correlatedObjects = objects.filter((o) => (o.linkedContainers?.length ?? 0) > 1);
    const uniqCorrelatedObjects = R.uniqBy(R.prop('id'), correlatedObjects);

    const correlatedContainers = uniqCorrelatedObjects.flatMap((o) => o.linkedContainers ?? []);
    const uniqCorrelatedContainers = R.uniqBy(R.prop('id'), correlatedContainers);

    const links = uniqCorrelatedObjects.flatMap((object) => {
      const objectCorrelatedContainers = R.uniqBy(R.prop('id'), (object.linkedContainers ?? []));
      return objectCorrelatedContainers.map((container) => {
        // The link only places the object in the container: the inference and the confidence of the container are not the link's.
        return buildLink(container, {
          id: `${object.id}-${container.id}`,
          target: container.id,
          target_id: container.id,
          source: object.id,
          source_id: object.id,
          parent_types: ['basic-relationship', 'stix-meta-relationship'],
          entity_type: 'basic-relationship',
          relationship_type: 'reported-in',
          label: '',
          name: '',
          inferred: false,
          isNestedInferred: false,
          confidence: null,
        });
      });
    });

    const nodes = [...uniqCorrelatedObjects, ...uniqCorrelatedContainers].map((object) => {
      return buildNode(object, graphPositions);
    });

    return { links, nodes };
  };

  /**
   * Convert a relationship currently displayed as a link into a node in the graph.
   * This is needed when a relationship becomes the source or target of another relationship
   * (nested relationship): it can no longer be a simple link and must be represented as a node.
   * The conversion is done by:
   * - removing the existing direct link that represented this relationship,
   * - adding the relationship as a new node,
   * - creating two connector links: one from its source to the new node, and one from the new node to its target.
   */
  const buildGraphDataAfterRelationshipLinkToNodeConversion = (
    previousGraphData: LibGraphProps['graphData'] | undefined,
    rawObjects: ObjectToParse[],
    rawPositions: OctiGraphPositions,
    relObj: NonNullable<ObjectToParse['from']>,
  ) => {
    const nodeIds = previousGraphData?.nodes.map((n) => n.id) ?? [];

    // nothing to do if the object to transform is not a relationship
    if (!relObj.relationship_type) return previousGraphData;
    // nothing to do if the object to transform is already in the graph nodes (= if the relationship to transform is not displayed as a link but already as a node)
    if (nodeIds.includes(relObj.id)) return previousGraphData;

    const relRaw = rawObjects.find((o) => o.id === relObj.id);
    if (!relRaw) return previousGraphData;

    const nodeToAdd = buildNode(relRaw, rawPositions);
    const [linkToRelNode, linkFromRelNode] = buildNestedLinks(relRaw);

    // Defensive: should never filter anything since we already checked nodeIdSet above.
    const filteredNodes = (previousGraphData?.nodes ?? []).filter((n) => n.id !== nodeToAdd.id);
    // Remove the single link that was representing this relationship
    const filteredLinks = (previousGraphData?.links ?? []).filter((link) => link.id !== relRaw.id);

    return {
      nodes: [...filteredNodes, nodeToAdd],
      links: [...filteredLinks, linkToRelNode, linkFromRelNode],
    };
  };

  return {
    buildGraphData,
    buildCorrelationData,
    buildNode,
    buildLink,
    buildNestedLinks,
    isNestedRelationship,
    buildGraphDataAfterRelationshipLinkToNodeConversion,
  };
};

export default useGraphParser;
