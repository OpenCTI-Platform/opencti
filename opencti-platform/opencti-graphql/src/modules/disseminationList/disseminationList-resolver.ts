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
import { addDisseminationList, deleteDisseminationList, fieldPatchDisseminationList, findAll, findById, sendToDisseminationList } from './disseminationList-domain';

const disseminationListResolvers: Resolvers = {
  Query: {
    disseminationList: (_, { id }, context) => findById(context, context.user, id),
    disseminationLists: (_, args, context) => findAll(context, context.user, args),
  },
  DisseminationList: {},
  Mutation: {
    disseminationListAdd: (_, { input }, context) => {
      return addDisseminationList(context, context.user, input);
    },
    disseminationListDelete: (_, { id }, context) => {
      return deleteDisseminationList(context, context.user, id);
    },
    disseminationListFieldPatch: (_, { id, input }, context) => {
      return fieldPatchDisseminationList(context, context.user, id, input);
    },
    disseminationListSend: (_, { input }, context) => {
      return sendToDisseminationList(context, context.user, input);
    }
  }
};

export default disseminationListResolvers;
