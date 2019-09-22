import { map } from 'ramda';
import { filesListing } from '../database/minio';
import { buildPagination } from '../database/utils';

const filesResolvers = {
  Query: {
    files: async (_, { category, first, entityId, entityType }) => {
      const files = await filesListing(category, entityId, entityType);
      const fileNodes = map(f => ({ node: f }), files);
      return buildPagination(first, 0, fileNodes, files.length);
    }
  }
};

export default filesResolvers;
