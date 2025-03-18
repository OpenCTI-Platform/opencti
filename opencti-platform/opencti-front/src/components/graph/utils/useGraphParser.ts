import * as R from 'ramda';
import { dateFormat, jsDate } from '../../../utils/Time';
import { isNone, useFormatter } from '../../i18n';
import { defaultDate, getMainRepresentative } from '../../../utils/defaultRepresentatives';
import type { OctiGraphPositions, GraphLink, GraphNode } from '../graph.types';
import { truncate } from '../../../utils/String';
import GRAPH_IMAGES from './graphImages';
import { graphImages } from '../../../utils/Graph';
import { itemColor } from '../../../utils/Colors';

export interface ObjectToParse {
  id: string
  entity_type: string
  relationship_type: string
  parent_types: string[]
  types?: string[] | null | undefined
  is_inferred: boolean
  observable_value?: string
  observableName?: string
  x_opencti_color?: string
  x_opencti_additional_names?: string[]
  hashes?: {
    algorithm: string
    hash: string
  }[]
  color?: string
  numberOfConnectedElement?: number
  createdBy: {
    id: string
    name: string
  }
  created: string
  start_time: string
  stop_time: string
  first_seen: string
  last_seen: string
  from?: {
    id: string
    relationship_type?: string
    entity_type?: string
  }
  to?: {
    id: string
    relationship_type?: string
    entity_type?: string
  }
  objectMarking: {
    id: string
    definition: string
  }[]
  // Other containers associated to this object.
  // Used for correlation graphs.
  linkedContainers?: ObjectToParse[]
}

const useGraphParser = () => {
  const { t_i18n } = useFormatter();

  const getRelationshipName = (data: ObjectToParse, forNode = false) => {
    const key = forNode ? data.relationship_type : data.entity_type;
    const relTypeStr = `<strong>${t_i18n(`relationship_${key}`)}</strong>`;
    const createdStr = `${t_i18n('Created the')} ${dateFormat(data.created)}`;
    const start = data.start_time || data.first_seen;
    const startStr = `${t_i18n('Start time')} ${isNone(start) ? '-' : dateFormat(start)}`;
    const end = data.stop_time || data.last_seen;
    const endStr = `${t_i18n('Stop time')} ${isNone(end) ? '-' : dateFormat(end)}`;
    return `${relTypeStr}\n${createdStr}\n${startStr}\n${endStr}`;
  };

  const getMarkings = (data: ObjectToParse) => {
    let markedBy = [{
      id: 'abb8eb18-a02c-48e9-adae-08c92275c87e',
      definition: t_i18n('None'),
    }];
    if (data.objectMarking && data.objectMarking.length > 0) {
      markedBy = data.objectMarking.map((m) => ({ id: m.id, definition: m.definition }));
    }
    return markedBy;
  };

  const getCreatedBy = (data: ObjectToParse) => {
    return data.createdBy ? data.createdBy : {
      id: '0533fcc9-b9e8-4010-877c-174343cb24cd',
      name: t_i18n('None'),
    };
  };

  const getIsNestedInferred = (data: ObjectToParse) => {
    return (data.types?.includes('inferred') && !data.types.includes('manual')) || false;
  };

  const getNodeLabel = (data: ObjectToParse) => {
    if (data.parent_types.includes('basic-relationship')) {
      return t_i18n(`relationship_${data.relationship_type}`);
    } if (data.entity_type === 'StixFile' && data.observable_value) {
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
    return GRAPH_IMAGES[key] || graphImages.Unknown;
  };

  const getNodeName = (data: ObjectToParse) => {
    if (data.relationship_type) {
      return getRelationshipName(data, true);
    } if (data.entity_type === 'StixFile' && data.observable_value) {
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
      numberOfConnectedElement,
      ...getNodeImg(data),
      name: getNodeName(data),
      label: getNodeLabel(data),
      markedBy: getMarkings(data),
      createdBy: getCreatedBy(data),
      defaultDate: jsDate(defaultDate(data)),
      isNestedInferred: getIsNestedInferred(data),
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
      name: getRelationshipName(data),
      createdBy: getCreatedBy(data),
      defaultDate: jsDate(defaultDate(data)),
      isNestedInferred: getIsNestedInferred(data),
    };
    return {
      ...baseLink,
      ...(override ?? {}),
    };
  };

  const buildGraphData = (objects: ObjectToParse[], graphPositions: OctiGraphPositions) => {
    const uniqObjects = R.uniqBy(R.prop('id'), objects)
      .filter((object) => !['Note', 'Opinion'].includes(object.entity_type));
    const uniqIds = uniqObjects.map((o) => o.id);
    const relationshipsIdsInNestedRelationship = objects.flatMap((o) => {
      if (o.from && o.to && (o.from.relationship_type || o.to.relationship_type)) {
        return o.from?.relationship_type ? o.from.id : o.to.id;
      }
      return [];
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
        return [
          buildLink(o, { name: '', label: '', target: o.id, target_id: o.id }),
          buildLink(o, { name: '', label: '', source: o.id, source_id: o.id }),
        ];
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
        });
      });
    });

    const nodes = [...uniqCorrelatedObjects, ...uniqCorrelatedContainers].map((object) => {
      return buildNode(object, graphPositions);
    });

    return { links, nodes };
  };

  return { buildGraphData, buildCorrelationData, buildNode, buildLink };
};

export default useGraphParser;
