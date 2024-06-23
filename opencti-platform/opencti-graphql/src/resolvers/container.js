import {
  containersObjectsOfObject,
  findAll,
  findById,
  knowledgeAddFromInvestigation,
  objects,
  relatedContainers,
  containersNumber,
  containersNumberByAuthor,
  containersNumberByEntity
} from '../domain/container';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { investigationAddFromContainer } from '../modules/workspace/investigation-domain';

const containerResolvers = {
  Query: {
    container: (_, { id }, context) => findById(context, context.user, id),
    containers: (_, args, context) => findAll(context, context.user, args),
    containersObjectsOfObject: (_, args, context) => containersObjectsOfObject(context, context.user, args),
    containersNumber: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return containersNumberByEntity(context, context.user, args);
      }
      if (args.authorId && args.authorId.length > 0) {
        return containersNumberByAuthor(context, context.user, args);
      }
      return containersNumber(context, context.user, args);
    },
  },
  Container: {
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      return 'Unknown';
    },
    objects: (container, args, context) => objects(context, context.user, container.id, args),
    relatedContainers: (container, args, context) => relatedContainers(context, context.user, container.id, args),
  },
  // TODO Reactivate after official release of graphQL 17
  // StixObjectOrStixRelationshipRefConnection: {
  //   edges: async function* generateEdges(connection) {
  //     const t0 = new Date().getTime();
  //     const elements = connection.edges;
  //     // eslint-disable-next-line no-restricted-syntax
  //     for (const [idx, item] of elements.entries()) {
  //       // Check every Nth item (e.g. 20th) if the elapsed time is larger than 50 ms.
  //       // If so, break and divide work into chunks using setImmediate
  //       if (idx % 20 === 0 && idx > 0 && new Date().getTime() - t0 > 50) { // 20 MS of locking
  //         await new Promise((resolve) => {
  //           setImmediate(resolve);
  //         });
  //       }
  //       yield item;
  //     }
  //   }
  // },
  Mutation: {
    containerEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input, commitMessage, references }) => stixDomainObjectAddRelation(context, context.user, id, input, { commitMessage, references }),
      // eslint-disable-next-line max-len
      relationDelete: ({ toId, relationship_type: relationshipType, commitMessage, references }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType, { commitMessage, references }),
      investigationAdd: () => investigationAddFromContainer(context, context.user, id),
      knowledgeAddFromInvestigation: ({ workspaceId }) => knowledgeAddFromInvestigation(context, context.user, { containerId: id, workspaceId }),
    }),
  },
};

export default containerResolvers;
