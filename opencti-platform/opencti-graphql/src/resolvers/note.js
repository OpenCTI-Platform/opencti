import * as R from 'ramda';
import {
  addNote,
  findAll,
  findById,
  noteContainsStixObjectOrStixRelationship,
  notesDistributionByEntity,
  notesNumber,
  notesNumberByEntity,
  notesTimeSeries,
  notesTimeSeriesByAuthor,
  notesTimeSeriesByEntity
} from '../domain/note';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import {
  RELATION_CREATED_BY,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixMetaRelationship';
import { buildRefRelationKey, KNOWLEDGE_COLLABORATION, KNOWLEDGE_UPDATE } from '../schema/general';
import { BYPASS, isUserHasCapability } from '../utils/access';
import { ForbiddenAccess } from '../config/errors';
import { addIndividual } from '../domain/individual';
import { userSessionRefresh } from '../domain/user';

// Needs to have edit rights or needs to be creator of the note
const checkUserAccess = async (context, user, id) => {
  const userCapabilities = R.flatten(user.capabilities.map((c) => c.name.split('_')));
  const isAuthorized = userCapabilities.includes(BYPASS) || userCapabilities.includes(KNOWLEDGE_UPDATE);
  const note = await findById(context, user, id);
  const isCreator = note[RELATION_CREATED_BY] ? note[RELATION_CREATED_BY] === user.individual_id : false;
  const isCollaborationAllowed = userCapabilities.includes(KNOWLEDGE_COLLABORATION) && isCreator;
  const accessGranted = isAuthorized || isCollaborationAllowed;
  if (!accessGranted) throw ForbiddenAccess();
};

const noteResolvers = {
  Query: {
    note: (_, { id }, context) => findById(context, context.user, id),
    notes: (_, args, context) => findAll(context, context.user, args),
    notesTimeSeries: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return notesTimeSeriesByEntity(context, context.user, args);
      }
      if (args.authorId && args.authorId.length > 0) {
        return notesTimeSeriesByAuthor(context, context.user, args);
      }
      return notesTimeSeries(context, context.user, args);
    },
    notesNumber: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return notesNumberByEntity(context, context.user, args);
      }
      return notesNumber(context, context.user, args);
    },
    notesDistribution: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return notesDistributionByEntity(context, context.user, args);
      }
      return [];
    },
    noteContainsStixObjectOrStixRelationship: (_, args, context) => {
      return noteContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  NotesFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    objectContains: buildRefRelationKey(RELATION_OBJECT, '*')
  },
  Mutation: {
    noteEdit: (_, { id }, context) => ({
      delete: async () => {
        await checkUserAccess(context, context.user, id);
        return stixDomainObjectDelete(context, context.user, id);
      },
      fieldPatch: async ({ input, commitMessage, references }) => {
        await checkUserAccess(context, context.user, id);
        const isManager = isUserHasCapability(context.user, KNOWLEDGE_UPDATE);
        const availableInputs = isManager ? input : input.filter((i) => i.key !== 'createdBy');
        return stixDomainObjectEditField(context, context.user, id, availableInputs, { commitMessage, references });
      },
      contextPatch: async ({ input }) => {
        await checkUserAccess(context, context.user, id);
        return stixDomainObjectEditContext(context, context.user, id, input);
      },
      contextClean: async () => {
        await checkUserAccess(context, context.user, id);
        return stixDomainObjectCleanContext(context, context.user, id);
      },
      relationAdd: async ({ input }) => {
        await checkUserAccess(context, context.user, id);
        return stixDomainObjectAddRelation(context, context.user, id, input);
      },
      relationDelete: async ({ toId, relationship_type: relationshipType }) => {
        await checkUserAccess(context, context.user, id);
        return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
      },
    }),
    userNoteAdd: async (_, { input }, context) => {
      const { user } = context;
      let individualId = user.individual_id;
      if (individualId === undefined) {
        const individual = await addIndividual(context, user, { name: user.name, contact_information: user.user_email });
        individualId = individual.id;
        await userSessionRefresh(user.internal_id);
      }
      const inputWithCreator = { ...input, createdBy: individualId };
      return addNote(context, user, inputWithCreator);
    },
    noteAdd: (_, { input }, context) => {
      return addNote(context, context.user, input);
    },
  },
};

export default noteResolvers;
