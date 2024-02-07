/*
Copyright (c) 2021-2024 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { withFilter } from 'graphql-subscriptions';
import type { Resolvers } from '../../generated/graphql';
import { fixSpelling, generateContainerReport } from './ai-domain';
import { pubSubAsyncIterator } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { AI_BUS } from './ai-types';

const aiResolvers: Resolvers = {
  Mutation: {
    aiContainerGenerateReport: (_, args, context) => generateContainerReport(context, context.user, args),
    aiFixSpelling: (_, { id, content, format }, context) => fixSpelling(context, context.user, id, content, format),
  },
  Subscription: {
    aiBus: {
      resolve: /* v8 ignore next */ (payload: any) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        const asyncIterator = pubSubAsyncIterator(BUS_TOPICS[AI_BUS].EDIT_TOPIC);
        const filtering = withFilter(() => asyncIterator, (payload) => {
          return payload && payload.user.id === context.user.id && payload.instance.bus_id === id;
        })();
        return {
          [Symbol.asyncIterator]() {
            return filtering;
          }
        };
      },
    },
  },
};

export default aiResolvers;
