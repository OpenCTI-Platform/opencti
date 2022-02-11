import { findById, findAll, findTemplateById, findAllTemplates } from '../domain/status';
import type { Resolvers } from '../generated/graphql';

const statusResolvers: Resolvers = {
  Query: {
    statusTemplate: (_, { id }, { user }) => findTemplateById(user, id),
    statusTemplates: (_, args, { user }) => findAllTemplates(user, args),
    status: (_, { id }, { user }) => findById(user, id),
    statuses: (_, args, { user }) => findAll(user, args),
  },
  Status: {
    template: (current, _, { user }) => findTemplateById(user, current.template_id),
  },
};

export default statusResolvers;
