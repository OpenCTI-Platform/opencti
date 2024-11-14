/*
Copyright (c) 2021-2024 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { v4 as uuidv4 } from 'uuid';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { type EntityOptions, internalFindByIds, listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import type { DomainFindById } from '../../domain/domainTypes';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { AuthContext, AuthUser } from '../../types/user';
import type { EditInput, FilterGroup, PlaybookAddInput, PlaybookAddLinkInput, PlaybookAddNodeInput, PositionInput } from '../../generated/graphql';
import type { BasicStoreEntityPlaybook, ComponentDefinition, LinkDefinition, NodeDefinition } from './playbook-types';
import { ENTITY_TYPE_PLAYBOOK } from './playbook-types';
import { PLAYBOOK_COMPONENTS, PLAYBOOK_INTERNAL_DATA_CRON, type SharingConfiguration } from './playbook-components';
import { UnsupportedError } from '../../config/errors';
import { type BasicStoreEntityOrganization, ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';
import { SYSTEM_USER } from '../../utils/access';
import { validateFilterGroupForStixMatch } from '../../utils/filtering/filtering-stix/stix-filtering';
import { registerConnectorQueues, unregisterConnector } from '../../database/rabbitmq';
import { checkAndConvertFilters } from '../../utils/filtering/filtering-utils';

export const findById: DomainFindById<BasicStoreEntityPlaybook> = (context: AuthContext, user: AuthUser, playbookId: string) => {
  return storeLoadById(context, user, playbookId, ENTITY_TYPE_PLAYBOOK);
};

export const findAll = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityPlaybook>) => {
  return listEntitiesPaginated<BasicStoreEntityPlaybook>(context, user, [ENTITY_TYPE_PLAYBOOK], opts);
};

export const findAllPlaybooks = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityPlaybook>) => {
  return listAllEntities<BasicStoreEntityPlaybook>(context, user, [ENTITY_TYPE_PLAYBOOK], opts);
};

export const availableComponents = () => {
  return Object.values(PLAYBOOK_COMPONENTS);
};

export const getPlaybookDefinition = async (context: AuthContext, playbook: BasicStoreEntityPlaybook) => {
  if (playbook.playbook_definition && playbook.playbook_definition.includes('PLAYBOOK_SHARING_COMPONENT')) {
    // parse playbook definition in case there is a sharing with organization component, in order to parse organizations to get their label
    const definition = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
    const sharingComponent = definition.nodes.find((n) => n.component_id === 'PLAYBOOK_SHARING_COMPONENT');
    if (sharingComponent && sharingComponent.configuration) {
      const sharingConfiguration = JSON.parse(sharingComponent.configuration) as SharingConfiguration;
      const organizationsIds = sharingConfiguration.organizations.filter((o) => typeof o === 'string');
      if (organizationsIds.length === 0) {
        return playbook.playbook_definition; // nothing to map, already mapped
      }
      const organizationsByIds = await internalFindByIds(context, SYSTEM_USER, organizationsIds, {
        type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
        baseData: true,
        baseFields: ['internal_id', 'name'],
        toMap: true,
      }) as unknown as { [k: string]: BasicStoreEntityOrganization };
      const organizationsWithNames = [];
      for (let i = 0; i < organizationsIds.length; i += 1) {
        const orgId = organizationsIds[i];
        if (organizationsByIds[orgId]) {
          organizationsWithNames.push({ label: organizationsByIds[orgId].name, value: orgId });
        }
      }
      sharingConfiguration.organizations = organizationsWithNames;
      sharingComponent.configuration = JSON.stringify(sharingConfiguration);
      return JSON.stringify(definition);
    }
  }
  return playbook.playbook_definition;
};

const checkPlaybookFiltersAndBuildConfigWithCorrectFilters = (input: PlaybookAddNodeInput) => {
  if (!input.configuration) {
    return '{}';
  }
  let stringifiedFilters;
  const config = JSON.parse(input.configuration);
  if (config.filters) {
    const filterGroup = JSON.parse(config.filters) as FilterGroup;
    if (input.component_id === PLAYBOOK_INTERNAL_DATA_CRON.id) {
      stringifiedFilters = JSON.stringify(checkAndConvertFilters(filterGroup));
    } else { // our stix matching is currently limited, we need to validate the input filters
      validateFilterGroupForStixMatch(filterGroup);
      stringifiedFilters = config.filters;
    }
  }
  return JSON.stringify({ ...config, filters: stringifiedFilters });
};

export const playbookAddNode = async (context: AuthContext, user: AuthUser, id: string, input: PlaybookAddNodeInput) => {
  const configuration = checkPlaybookFiltersAndBuildConfigWithCorrectFilters(input);

  const playbook = await findById(context, user, id);
  const definition = JSON.parse(playbook.playbook_definition ?? '{}') as ComponentDefinition;
  const relatedComponent = PLAYBOOK_COMPONENTS[input.component_id];
  if (!relatedComponent) {
    throw UnsupportedError('Playbook related component not found');
  }
  const existingEntryPoint = definition.nodes.find((n) => PLAYBOOK_COMPONENTS[n.component_id]?.is_entry_point);
  if (relatedComponent.is_entry_point && existingEntryPoint) {
    throw UnsupportedError('Playbook multiple entrypoint is not supported');
  }
  const nodeId = uuidv4();
  definition.nodes.push({
    id: nodeId,
    name: input.name,
    position: input.position,
    component_id: input.component_id,
    configuration, // TODO Check valid json
  });
  const patch: any = { playbook_definition: JSON.stringify(definition) };
  if (relatedComponent.is_entry_point) {
    patch.playbook_start = nodeId;
  }
  const { element: updatedElem } = await patchAttribute(context, user, id, ENTITY_TYPE_PLAYBOOK, patch);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, updatedElem, user).then(() => nodeId);
};

const deleteLinksAndAllChildren = (definition: ComponentDefinition, links: LinkDefinition[]) => {
  // Resolve all nodes to delete
  const linksToDelete = links;
  const nodesToDelete = [] as NodeDefinition[];
  let childrenLinks = [] as LinkDefinition[];
  // Resolve children nodes
  let childrenNodes = definition.nodes.filter((n) => links.map((o) => o.to.id).includes(n.id));
  if (childrenNodes.length > 0) {
    nodesToDelete.push(...childrenNodes);
    childrenLinks = definition.links.filter((n) => childrenNodes.map((o) => o.id).includes(n.from.id));
  }
  while (childrenLinks.length > 0) {
    linksToDelete.push(...childrenLinks);
    // Resolve children nodes not already in nodesToDelete
    childrenNodes = definition.nodes.filter((n) => linksToDelete.map((o) => o.to.id).includes(n.id) && !nodesToDelete.map((o) => o.id).includes(n.id));
    if (childrenNodes.length > 0) {
      nodesToDelete.push(...childrenNodes);
      // eslint-disable-next-line @typescript-eslint/no-loop-func
      childrenLinks = definition.links.filter((n) => childrenNodes.map((o) => o.id).includes(n.from.id));
    } else {
      childrenLinks = [];
    }
    logApp.info('Delete links and children loop', { nodesToDelete, linksToDelete });
  }
  return {
    nodes: definition.nodes.filter((n) => !nodesToDelete.map((o) => o.id).includes(n.id)),
    links: definition.links.filter((n) => !linksToDelete.map((o) => o.id).includes(n.id))
  };
};

export const playbookUpdatePositions = async (context: AuthContext, user: AuthUser, id: string, positions: string) => {
  const playbook = await findById(context, user, id);
  const definition = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
  const nodesPositions = JSON.parse(positions);
  definition.nodes = definition.nodes.map((n) => {
    const position = nodesPositions.filter((o: { id: string, position: PositionInput }) => o.id === n.id).at(0);
    if (position) {
      return {
        ...n,
        position: position.position
      };
    }
    return n;
  });
  const patch: any = { playbook_definition: JSON.stringify(definition) };
  return patchAttribute(context, user, id, ENTITY_TYPE_PLAYBOOK, patch).then(() => id);
};

export const playbookReplaceNode = async (context: AuthContext, user: AuthUser, id: string, nodeId: string, input: PlaybookAddNodeInput) => {
  const configuration = checkPlaybookFiltersAndBuildConfigWithCorrectFilters(input);

  const playbook = await findById(context, user, id);
  const definition = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
  const relatedComponent = PLAYBOOK_COMPONENTS[input.component_id];
  if (!relatedComponent) {
    throw UnsupportedError('Playbook related component not found');
  }
  const existingEntryPoint = definition.nodes.filter((n) => n.id !== nodeId).find((n) => PLAYBOOK_COMPONENTS[n.component_id]?.is_entry_point);
  if (relatedComponent.is_entry_point && existingEntryPoint) {
    throw UnsupportedError('Playbook multiple entrypoint is not supported');
  }
  // We need to re-compute port mapping
  const oldComponentId = definition.nodes.filter((n) => n.id === nodeId).at(0)?.component_id;
  if (!oldComponentId) {
    throw UnsupportedError('Old component not found');
  }
  const oldComponent = PLAYBOOK_COMPONENTS[oldComponentId];
  if (oldComponent.ports.length > relatedComponent.ports.length) {
    // eslint-disable-next-line no-plusplus
    for (let i = oldComponent.ports.length - 1; i >= relatedComponent.ports.length; i--) {
      // Find all links to the port
      const linksToDelete = definition.links.filter((n) => n.from.id === nodeId && n.from.port === oldComponent.ports[i].id);
      const result = deleteLinksAndAllChildren(definition, linksToDelete);
      definition.nodes = result.nodes;
      definition.links = result.links;
    }
  }
  // Replace the node
  definition.nodes = definition.nodes.map((n) => {
    if (n.id === nodeId) {
      return {
        id: nodeId,
        name: input.name,
        position: input.position,
        component_id: input.component_id,
        configuration, // TODO Check valid json
      };
    }
    return n;
  });
  const patch: any = { playbook_definition: JSON.stringify(definition) };
  const { element: updatedElem } = await patchAttribute(context, user, id, ENTITY_TYPE_PLAYBOOK, patch);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, updatedElem, user).then(() => nodeId);
};

// eslint-disable-next-line max-len
export const playbookInsertNode = async (context: AuthContext, user: AuthUser, id: string, parentNodeId: string, parentPortId: string, childNodeId: string, input: PlaybookAddNodeInput) => {
  const playbook = await findById(context, user, id);
  const definition = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
  const relatedComponent = PLAYBOOK_COMPONENTS[input.component_id];
  if (!relatedComponent) {
    throw UnsupportedError('Playbook related component not found');
  }
  const existingEntryPoint = definition.nodes.find((n) => PLAYBOOK_COMPONENTS[n.component_id]?.is_entry_point);
  if (relatedComponent.is_entry_point && existingEntryPoint) {
    throw UnsupportedError('Playbook multiple entrypoint is not supported');
  }
  // Add the new node
  const nodeId = uuidv4();
  definition.nodes.push({
    id: nodeId,
    name: input.name,
    position: input.position,
    component_id: input.component_id,
    configuration: input.configuration ?? '{}' // TODO Check valid json
  });
  // Replace node with new position
  definition.nodes = definition.nodes.map((n) => {
    if (n.id === childNodeId) {
      return {
        ...n,
        position: {
          x: n.position.x,
          y: n.position.y + 150,
        }
      };
    }
    return n;
  });
  // Replace links
  // Build the link between the new node and the parent
  const linkId = uuidv4();
  definition.links.push({
    id: linkId,
    from: {
      id: parentNodeId,
      port: parentPortId,
    },
    to: {
      id: nodeId
    }
  });
  // Replace the link
  if (relatedComponent.ports.length > 0) {
    definition.links = definition.links.map((n) => {
      if (n.from.id === parentNodeId && n.from.port === parentPortId && n.to.id === childNodeId) {
        return {
          ...n,
          from: {
            id: nodeId,
            port: relatedComponent.ports.at(0)?.id ?? 'out',
          },
          to: {
            id: childNodeId
          }
        };
      }
      return n;
    });
  } else {
    // Delete the child node ID
    definition.nodes = definition.nodes.filter((n) => n.id !== childNodeId);
    // Also delete all links going to this node (all links from this node are deleted after)
    definition.links = definition.links.filter((n) => n.to.id !== childNodeId);
    const linksToDelete = definition.links.filter((n) => n.from.id === childNodeId);
    const result = deleteLinksAndAllChildren(definition, linksToDelete);
    definition.nodes = result.nodes;
    definition.links = result.links;
  }
  const patch: any = { playbook_definition: JSON.stringify(definition) };
  const { element: updatedElem } = await patchAttribute(context, user, id, ENTITY_TYPE_PLAYBOOK, patch);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, updatedElem, user).then(() => ({ nodeId, linkId }));
};

export const playbookDeleteNode = async (context: AuthContext, user: AuthUser, id: string, nodeId: string) => {
  const playbook = await findById(context, user, id);
  const definition = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
  definition.nodes = definition.nodes.filter((n) => n.id !== nodeId);
  // Also delete all links going to this node (all links from this node are deleted after)
  definition.links = definition.links.filter((n) => n.to.id !== nodeId);
  // Delete all children
  const linksToDelete = definition.links.filter((n) => n.from.id === nodeId);
  const result = deleteLinksAndAllChildren(definition, linksToDelete);
  definition.nodes = result.nodes;
  definition.links = result.links;
  const patch: any = { playbook_definition: JSON.stringify(definition) };
  const { element: updatedElem } = await patchAttribute(context, user, id, ENTITY_TYPE_PLAYBOOK, patch);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, updatedElem, user);
};

export const playbookAddLink = async (context: AuthContext, user: AuthUser, id: string, input: PlaybookAddLinkInput) => {
  const playbook = await findById(context, user, id);
  const definition = JSON.parse(playbook.playbook_definition ?? '{}') as ComponentDefinition;
  // Check from consistency
  const node = definition.nodes.find((n) => n.id === input.from_node);
  if (!node) {
    throw UnsupportedError('Playbook link node from not found');
  }
  const nodePort = PLAYBOOK_COMPONENTS[node.component_id].ports.find((p) => p.id === input.from_port);
  if (!nodePort || nodePort.type === 'in') {
    throw UnsupportedError('Playbook link invalid from configuration');
  }
  // Check existing link
  const existingLink = definition.links.find((l) => l.from.id === input.from_node && l.from.port === input.from_port && l.to.id === input.to_node);
  if (existingLink) {
    throw UnsupportedError('Playbook link duplication is not possible');
  }
  // Check to consistency
  const toNode = definition.nodes.find((n) => n.id === input.to_node);
  if (!toNode) {
    throw UnsupportedError('Playbook link node from not found');
  }
  // Build the link
  const linkId = uuidv4();
  definition.links.push({
    id: linkId,
    from: {
      id: input.from_node,
      port: input.from_port
    },
    to: {
      id: input.to_node
    }
  });
  const patch = { playbook_definition: JSON.stringify(definition) };
  const { element: updatedElem } = await patchAttribute(context, user, id, ENTITY_TYPE_PLAYBOOK, patch);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, updatedElem, user).then(() => linkId);
};

export const playbookDeleteLink = async (context: AuthContext, user: AuthUser, id: string, linkId: string) => {
  const playbook = await findById(context, user, id);
  const definition = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
  definition.links = definition.links.filter((n) => n.id !== linkId);
  const patch: any = { playbook_definition: JSON.stringify(definition) };
  const { element: updatedElem } = await patchAttribute(context, user, id, ENTITY_TYPE_PLAYBOOK, patch);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, updatedElem, user);
};

export const playbookAdd = async (context: AuthContext, user: AuthUser, input: PlaybookAddInput) => {
  const playbook_definition = JSON.stringify({ nodes: [], links: [] });
  const playbook = { ...input, playbook_definition, playbook_running: false };
  const created = await createEntity(context, user, playbook, ENTITY_TYPE_PLAYBOOK);
  const playbookId = created.internal_id;
  await registerConnectorQueues(playbookId, `Playbook ${playbookId} queue`, 'internal', 'playbook');
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, created, user);
};

export const playbookDelete = async (context: AuthContext, user: AuthUser, playbookId: string) => {
  const element = await deleteElementById(context, user, playbookId, ENTITY_TYPE_PLAYBOOK);
  await unregisterConnector(playbookId);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, element, user).then(() => playbookId);
};

export const playbookEdit = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  const { element: updatedElem } = await updateAttribute(context, user, id, ENTITY_TYPE_PLAYBOOK, input);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, updatedElem, user);
};
