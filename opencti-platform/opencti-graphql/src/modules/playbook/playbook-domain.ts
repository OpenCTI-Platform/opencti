/*
Copyright (c) 2021-2025 Filigran SAS

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
import type { FileHandle } from 'fs/promises';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { createEntity, deleteElementById, patchAttribute, stixLoadById, updateAttribute } from '../../database/middleware';
import { type EntityOptions, internalFindByIds, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import type { DomainFindById } from '../../domain/domainTypes';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { AuthContext, AuthUser } from '../../types/user';
import {
  type EditInput,
  type FilterGroup,
  FilterMode,
  type PlaybookAddInput,
  type PlaybookAddLinkInput,
  type PlaybookAddNodeInput,
  type PositionInput
} from '../../generated/graphql';
import type { BasicStoreEntityPlaybook, ComponentDefinition, LinkDefinition, NodeDefinition } from './playbook-types';
import { ENTITY_TYPE_PLAYBOOK } from './playbook-types';
import { PLAYBOOK_COMPONENTS, PLAYBOOK_INTERNAL_DATA_CRON, type SharingConfiguration, type StreamConfiguration } from './playbook-components';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { type BasicStoreEntityOrganization, ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';
import { isStixMatchFilterGroup, validateFilterGroupForStixMatch } from '../../utils/filtering/filtering-stix/stix-filtering';
import { registerConnectorQueues, unregisterConnector } from '../../database/rabbitmq';
import { getEntitiesListFromCache } from '../../database/cache';
import { SYSTEM_USER } from '../../utils/access';
import { findFiltersFromKey, checkAndConvertFilters } from '../../utils/filtering/filtering-utils';
import { elFindByIds } from '../../database/engine';
import { checkEnterpriseEdition, isEnterpriseEdition } from '../../enterprise-edition/ee';
import pjson from '../../../package.json';
import { extractContentFrom } from '../../utils/fileToContent';
import { publishUserAction } from '../../listener/UserActionListener';
import { isCompatibleVersionWithMinimal } from '../../utils/version';
import { buildPagination } from '../../database/utils';
import type { BasicStoreObject } from '../../types/store';

const MINIMAL_COMPATIBLE_VERSION = '6.7.14';

export const findById: DomainFindById<BasicStoreEntityPlaybook> = async (context: AuthContext, user: AuthUser, playbookId: string) => {
  await checkEnterpriseEdition(context);
  return storeLoadById(context, user, playbookId, ENTITY_TYPE_PLAYBOOK);
};

export const findPlaybookPaginated = async (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityPlaybook>) => {
  const isEE = await isEnterpriseEdition(context);
  if (!isEE) {
    return buildPagination(0, null, [], 0);
  }
  return pageEntitiesConnection<BasicStoreEntityPlaybook>(context, user, [ENTITY_TYPE_PLAYBOOK], opts);
};

export const findPlaybooksForEntity = async (context: AuthContext, user: AuthUser, id: string) => {
  const isEE = await isEnterpriseEdition(context);
  if (!isEE) {
    return [];
  }
  const stixEntity = await stixLoadById(context, user, id);
  const playbooks = await getEntitiesListFromCache<BasicStoreEntityPlaybook>(context, SYSTEM_USER, ENTITY_TYPE_PLAYBOOK);
  const filteredPlaybooks = [];
  for (let playbookIndex = 0; playbookIndex < playbooks.length; playbookIndex += 1) {
    const playbook = playbooks[playbookIndex];
    if (playbook.playbook_definition) {
      const def = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
      const instance = def.nodes.find((n) => n.id === playbook.playbook_start);
      if (instance && (instance.component_id === 'PLAYBOOK_INTERNAL_DATA_STREAM' || instance.component_id === 'PLAYBOOK_INTERNAL_MANUAL_TRIGGER')) {
        const { filters } = (JSON.parse(instance.configuration ?? '{}') as StreamConfiguration);
        const jsonFilters = filters ? JSON.parse(filters) : null;
        const newFilters = {
          mode: FilterMode.And,
          filters: findFiltersFromKey(jsonFilters?.filters ?? [], 'entity_type'),
          filterGroups: []
        };
        const isMatch = await isStixMatchFilterGroup(context, SYSTEM_USER, stixEntity, newFilters);
        if (isMatch) {
          filteredPlaybooks.push(playbook);
        }
      }
    }
  }
  return filteredPlaybooks;
};

export const availableComponents = async (context: AuthContext) => {
  await checkEnterpriseEdition(context);
  return Object.values(PLAYBOOK_COMPONENTS);
};

export const getPlaybookDefinition = async (context: AuthContext, playbook: BasicStoreEntityPlaybook) => {
  await checkEnterpriseEdition(context);
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

const checkPlaybookFiltersAndBuildConfigWithCorrectFilters = async (
  context: AuthContext,
  user: AuthUser,
  input: PlaybookAddNodeInput,
  userId: string
) => {
  if (!input.configuration) {
    return '{}';
  }
  let stringifiedFilters;
  const config = JSON.parse(input.configuration);
  if (config.filters) {
    const filterGroup = JSON.parse(config.filters) as FilterGroup;
    if (input.component_id === PLAYBOOK_INTERNAL_DATA_CRON.id) {
      const findIds = elFindByIds as (context: AuthContext, user: AuthUser, ids: string[], opts: any) => Promise<Record<string, BasicStoreObject>>;
      const convertedFilters = await checkAndConvertFilters(context, user, filterGroup, userId, findIds, { noFiltersConvert: true });
      stringifiedFilters = JSON.stringify(convertedFilters);
    } else { // our stix matching is currently limited, we need to validate the input filters
      validateFilterGroupForStixMatch(filterGroup);
      stringifiedFilters = config.filters;
    }
  }
  return JSON.stringify({ ...config, filters: stringifiedFilters });
};

export const playbookAddNode = async (context: AuthContext, user: AuthUser, id: string, input: PlaybookAddNodeInput) => {
  await checkEnterpriseEdition(context);
  const configuration = await checkPlaybookFiltersAndBuildConfigWithCorrectFilters(context, user, input, user.id);
  const playbook = await findById(context, user, id);
  const definition = JSON.parse(playbook.playbook_definition ?? '{}') as ComponentDefinition;
  const relatedComponent = PLAYBOOK_COMPONENTS[input.component_id];
  if (!relatedComponent) {
    throw UnsupportedError('Playbook related component not found', { input });
  }
  const existingEntryPoint = definition.nodes.find((n) => PLAYBOOK_COMPONENTS[n.component_id]?.is_entry_point);
  if (relatedComponent.is_entry_point && existingEntryPoint) {
    throw UnsupportedError('Playbook multiple entrypoint is not supported', { input });
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
  await checkEnterpriseEdition(context);
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

export const playbookReplaceNode = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  nodeId: string,
  input: PlaybookAddNodeInput
) => {
  await checkEnterpriseEdition(context);
  const configuration = await checkPlaybookFiltersAndBuildConfigWithCorrectFilters(context, user, input, user.id);

  const playbook = await findById(context, user, id);
  const definition = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
  const relatedComponent = PLAYBOOK_COMPONENTS[input.component_id];
  if (!relatedComponent) {
    throw UnsupportedError('Playbook related component not found', { id: input.component_id });
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

export const playbookInsertNode = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  parentNodeId: string,
  parentPortId: string,
  childNodeId: string,
  input: PlaybookAddNodeInput
) => {
  await checkEnterpriseEdition(context);
  const playbook = await findById(context, user, id);
  const definition = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
  const relatedComponent = PLAYBOOK_COMPONENTS[input.component_id];
  if (!relatedComponent) {
    throw UnsupportedError('Playbook related component not found', { id: input.component_id });
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
  await checkEnterpriseEdition(context);
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
  await checkEnterpriseEdition(context);
  const playbook = await findById(context, user, id);
  const definition = JSON.parse(playbook.playbook_definition ?? '{}') as ComponentDefinition;
  // Check from consistency
  const node = definition.nodes.find((n) => n.id === input.from_node);
  if (!node) {
    throw UnsupportedError('Playbook link node from not found', { id: input.from_node });
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
    throw UnsupportedError('Playbook link node from not found', { id: input.to_node });
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
  await checkEnterpriseEdition(context);
  const playbook = await findById(context, user, id);
  const definition = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
  definition.links = definition.links.filter((n) => n.id !== linkId);
  const patch: any = { playbook_definition: JSON.stringify(definition) };
  const { element: updatedElem } = await patchAttribute(context, user, id, ENTITY_TYPE_PLAYBOOK, patch);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, updatedElem, user);
};

type PlaybookCreationType = {
  name: string,
  description?: string | null,
  playbook_start?: string,
  playbook_running?: boolean,
  playbook_mode?: string,
  playbook_definition?: string
};
const createPlaybook = async (context: AuthContext, user: AuthUser, playbookCreationInput: PlaybookCreationType) => {
  await checkEnterpriseEdition(context);
  const created = await createEntity(context, user, playbookCreationInput, ENTITY_TYPE_PLAYBOOK);
  const playbookId = created.internal_id;
  await registerConnectorQueues(playbookId, `Playbook ${playbookId} queue`, 'internal', 'playbook');
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, created, user);
};

export const playbookAdd = async (context: AuthContext, user: AuthUser, input: PlaybookAddInput) => {
  const playbook_definition = JSON.stringify({ nodes: [], links: [] });
  const fullPlaybookInput = { ...input, playbook_definition, playbook_running: false };
  return createPlaybook(context, user, fullPlaybookInput);
};

export const playbookDelete = async (context: AuthContext, user: AuthUser, playbookId: string) => {
  await checkEnterpriseEdition(context);
  const element = await deleteElementById(context, user, playbookId, ENTITY_TYPE_PLAYBOOK);
  await unregisterConnector(playbookId);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, element, user).then(() => playbookId);
};

export const playbookEdit = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  await checkEnterpriseEdition(context);
  const { element: updatedElem } = await updateAttribute(context, user, id, ENTITY_TYPE_PLAYBOOK, input);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, updatedElem, user);
};

export const playbookExport = async (playbook: BasicStoreEntityPlaybook) => {
  const { name, description, playbook_mode, playbook_start, playbook_definition } = playbook;
  return JSON.stringify({
    openCTI_version: pjson.version,
    type: 'playbook',
    configuration: {
      name,
      description,
      playbook_mode,
      playbook_start,
      playbook_definition,
    }
  });
};

export const playbookImport = async (context: AuthContext, user: AuthUser, file: Promise<FileHandle>) => {
  const parsedData = await extractContentFrom(file);
  // check platform version compatibility
  if (!isCompatibleVersionWithMinimal(parsedData.openCTI_version, MINIMAL_COMPATIBLE_VERSION)) {
    throw FunctionalError(
      `Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: ${MINIMAL_COMPATIBLE_VERSION}`,
      { reason: parsedData.openCTI_version },
    );
  }
  if (parsedData.type !== 'playbook') {
    throw FunctionalError('Invalid import type, must be playbook', { type: parsedData.type });
  }
  const config = parsedData.configuration;
  const importData = {
    name: config.name,
    description: config.description,
    playbook_start: config.playbook_start,
    playbook_running: false,
    playbook_mode: config.playbook_mode,
    playbook_definition: config.playbook_definition,
  };
  const importPlaybook = await createPlaybook(context, user, importData);
  const importPlaybookId = importPlaybook.id;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `import ${importPlaybook.name} playbook`,
    context_data: {
      id: importPlaybookId,
      entity_type: ENTITY_TYPE_PLAYBOOK,
      input: importPlaybook,
    },
  });
  return importPlaybookId;
};

export const playbookDuplicate = async (context: AuthContext, user: AuthUser, id: string) => {
  const playbook = await findById(context, user, id);
  const newPlaybook = {
    name: `${playbook.name} - copy`,
    description: playbook.description,
    playbook_running: false,
    playbook_start: playbook.playbook_start,
    playbook_mode: playbook.playbook_mode,
    playbook_definition: playbook.playbook_definition,
  };
  const importPlaybook = await createEntity(context, user, newPlaybook, ENTITY_TYPE_PLAYBOOK);
  const importPlaybookId = importPlaybook.id;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `duplicate ${importPlaybook.name} playbook`,
    context_data: {
      id: importPlaybookId,
      entity_type: ENTITY_TYPE_PLAYBOOK,
      input: importPlaybook,
    },
  });
  return importPlaybookId;
};
