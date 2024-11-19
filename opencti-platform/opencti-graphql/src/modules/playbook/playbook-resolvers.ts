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

import type { Resolvers } from '../../generated/graphql';
import {
  playbookAdd,
  playbookDelete,
  playbookEdit,
  findById,
  findAll,
  availableComponents,
  playbookAddNode,
  playbookInsertNode,
  playbookReplaceNode,
  playbookAddLink,
  playbookDeleteNode,
  playbookDeleteLink,
  playbookUpdatePositions,
  findPlaybooksForEntity,
  getPlaybookDefinition
} from './playbook-domain';
import { executePlaybookOnEntity, playbookStepExecution } from '../../manager/playbookManager';
import { getLastPlaybookExecutions } from '../../database/redis';
import { getConnectorQueueSize } from '../../database/rabbitmq';

const playbookResolvers: Resolvers = {
  Query: {
    playbook: (_, { id }, context) => findById(context, context.user, id),
    playbooks: (_, args, context) => findAll(context, context.user, args),
    playbooksForEntity: (_, { id }, context) => findPlaybooksForEntity(context, context.user, id),
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    playbookComponents: () => availableComponents(),
  },
  Playbook: {
    playbook_definition: async (current, _, context) => getPlaybookDefinition(context, current),
    last_executions: async (current) => getLastPlaybookExecutions(current.id),
    queue_messages: async (current, _, context) => getConnectorQueueSize(context, context.user, current.id)
  },
  PlaybookComponent: {
    configuration_schema: async (current) => {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      const configurationSchema = await current.schema();
      return JSON.stringify(configurationSchema ?? '{}');
    }
  },
  Mutation: {
    playbookAdd: (_, { input }, context) => playbookAdd(context, context.user, input),
    playbookAddNode: (_, { id, input }, context) => playbookAddNode(context, context.user, id, input),
    playbookAddLink: (_, { id, input }, context) => playbookAddLink(context, context.user, id, input),
    playbookReplaceNode: (_, { id, nodeId, input }, context) => playbookReplaceNode(context, context.user, id, nodeId, input),
    playbookInsertNode: (_, { id, parentNodeId, parentPortId, childNodeId, input }, context) => {
      return playbookInsertNode(context, context.user, id, parentNodeId, parentPortId, childNodeId, input);
    },
    playbookDelete: (_, { id }, context) => playbookDelete(context, context.user, id),
    playbookDeleteNode: (_, { id, nodeId }, context) => playbookDeleteNode(context, context.user, id, nodeId),
    playbookDeleteLink: (_, { id, linkId }, context) => playbookDeleteLink(context, context.user, id, linkId),
    playbookUpdatePositions: (_, { id, positions }, context) => playbookUpdatePositions(context, context.user, id, positions),
    playbookFieldPatch: (_, { id, input }, context) => playbookEdit(context, context.user, id, input),
    playbookStepExecution: (_, args, context) => playbookStepExecution(context, context.user, args),
    playbookExecute: (_, { id, entityId }, context) => executePlaybookOnEntity(context, id, entityId),
  },
};

export default playbookResolvers;
