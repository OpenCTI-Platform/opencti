import type {File, Resolvers} from '../../generated/graphql';
import { addFintelDesign, findAll, findById, fintelDesignDelete, fintelDesignEditField } from './fintelDesign-domain';
import {paginatedForPathWithEnrichment} from "../internal/document/document-domain";
import {ENTITY_TYPE_FINTEL_TEMPLATE} from "../fintelTemplate/fintelTemplate-types";
import {ENTITY_TYPE_FINTEL_DESIGN} from "./fintelDesign-types";
import type {BasicStoreEntityDocument} from "../internal/document/document-types";

const fintelDesignResolvers: Resolvers = {
  Query: {
    fintelDesign: (_, { id }, context) => findById(context, context.user, id),
    fintelDesigns: (_, args, context) => {
      return findAll(context, context.user, args);
    },
  },
  FintelDesign: {
    importFiles: (fintelDesign: BasicStoreEntityDocument, { first }, context) => {
      const opts = { first, entity_id: fintelDesign.id, entity_type: ENTITY_TYPE_FINTEL_DESIGN };
      return paginatedForPathWithEnrichment(context, context.user, `import/${ENTITY_TYPE_FINTEL_DESIGN}/${fintelDesign.id}`, fintelDesign.id, opts);
    },
  },
  Mutation: {
    fintelDesignAdd: (_, { input }, context) => {
      return addFintelDesign(context, context.user, input);
    },
    fintelDesignDelete: (_, { id }, context) => {
      return fintelDesignDelete(context, context.user, id);
    },
    fintelDesignFieldPatch: (_, args, context) => {
      return fintelDesignEditField(context, context.user, args);
    },
  },
};

export default fintelDesignResolvers;
