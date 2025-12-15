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

import type { Resolvers } from '../../generated/graphql';
import {
  deletePir,
  findPirPaginated,
  findPirRelationPaginated,
  findById,
  findPirContainers,
  findPirHistory,
  pirAdd,
  pirEditAuthorizedMembers,
  pirFlagElement,
  pirRelationshipsDistribution,
  pirRelationshipsMultiTimeSeries,
  pirUnflagElement,
  updatePir,
} from './pir-domain';
import { getAuthorizedMembers } from '../../utils/authorizedMembers';
import { filterMembersUsersWithUsersOrgs, getUserAccessRight } from '../../utils/access';
import { getConnectorQueueSize } from '../../database/rabbitmq';

const pirResolvers: Resolvers = {
  Query: {
    pir: (_, { id }, context) => findById(context, context.user, id),
    pirs: (_, args, context) => findPirPaginated(context, context.user, args),
    pirRelationships: (_, args, context) => findPirRelationPaginated(context, context.user, args),
    pirRelationshipsDistribution: (_, args, context) => pirRelationshipsDistribution(context, context.user, args),
    pirRelationshipsMultiTimeSeries: (_, args, context) => pirRelationshipsMultiTimeSeries(context, context.user, args),
    pirLogs: (_, args, context) => findPirHistory(context, context.user, args),
  },
  Pir: {
    creators: async (pir, _, context) => {
      const creators = await context.batch.creatorsBatchLoader.load(pir.creator_id);
      if (!creators) {
        return [];
      }
      return filterMembersUsersWithUsersOrgs(context, context.user, creators);
    },
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    pirContainers: (pir, args, context) => findPirContainers(context, context.user, pir, args),
    authorizedMembers: (pir, _, context) => getAuthorizedMembers(context, context.user, pir),
    currentUserAccessRight: (pir, _, context) => getUserAccessRight(context.user, pir),
    queue_messages: async (pir, _, context) => getConnectorQueueSize(context, context.user, pir.id),
  },
  PirRelationship: {
    from: (rel, _, context) => (rel.from ? rel.from : context.batch.idsBatchLoader.load({ id: rel.fromId, type: rel.fromType })),
    to: (rel, _, context) => (rel.to ? rel.to : context.batch.idsBatchLoader.load({ id: rel.toId, type: rel.toType })),
  },
  Mutation: {
    pirAdd: (_, { input }, context) => pirAdd(context, context.user, input),
    pirFieldPatch: (_, { id, input }, context) => updatePir(context, context.user, id, input),
    pirEditAuthorizedMembers: (_, { id, input }, context) => pirEditAuthorizedMembers(context, context.user, id, input),
    pirDelete: (_, { id }, context) => deletePir(context, context.user, id),
    pirFlagElement: (_, { id, input }, context) => pirFlagElement(context, context.user, id, input),
    pirUnflagElement: (_, { id, input }, context) => pirUnflagElement(context, context.user, id, input),
  },
};

export default pirResolvers;
