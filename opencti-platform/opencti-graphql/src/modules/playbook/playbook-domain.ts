/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { v4 as uuidv4 } from 'uuid';
import { BUS_TOPICS } from '../../config/conf';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { type EntityOptions, listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import type { DomainFindById } from '../../domain/domainTypes';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { AuthContext, AuthUser } from '../../types/user';
import type { EditInput, PlaybookAddInput, PlaybookAddNodeInput, PlaybookAddLinkInput } from '../../generated/graphql';
import type { BasicStoreEntityPlaybook, ComponentDefinition } from './playbook-types';
import { ENTITY_TYPE_PLAYBOOK } from './playbook-types';
import { PLAYBOOK_COMPONENTS } from './playbook-components';
import { UnsupportedError } from '../../config/errors';

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

export const playbookAddNode = async (context: AuthContext, user: AuthUser, input: PlaybookAddNodeInput) => {
  const playbook = await findById(context, user, input.playbook_id);
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
    configuration: input.configuration ?? '{}' // TODO Check valid json
  });
  const patch: any = { playbook_definition: JSON.stringify(definition) };
  if (relatedComponent.is_entry_point) {
    patch.playbook_start = nodeId;
  }
  await patchAttribute(context, user, input.playbook_id, ENTITY_TYPE_PLAYBOOK, patch);
  return nodeId;
};

export const playbookDeleteNode = async (context: AuthContext, user: AuthUser, id: string, nodeId: string) => {
  const playbook = await findById(context, user, id);
  const definition = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
  definition.nodes = definition.nodes.filter((n) => n.id !== nodeId);
  const patch: any = { playbook_definition: JSON.stringify(definition) };
  const { element: updatedElem } = await patchAttribute(context, user, id, ENTITY_TYPE_PLAYBOOK, patch);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, updatedElem, user);
};

export const playbookAddLink = async (context: AuthContext, user: AuthUser, input: PlaybookAddLinkInput) => {
  const playbook = await findById(context, user, input.playbook_id);
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
  await patchAttribute(context, user, input.playbook_id, ENTITY_TYPE_PLAYBOOK, patch);
  return linkId;
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
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, created, user);
};

export const playbookDelete = async (context: AuthContext, user: AuthUser, id: string) => {
  const element = await deleteElementById(context, user, id, ENTITY_TYPE_PLAYBOOK);
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, element, user);
  return id;
};

export const playbookEdit = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  const { element: updatedElem } = await updateAttribute(context, user, id, ENTITY_TYPE_PLAYBOOK, input);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, updatedElem, user);
};
