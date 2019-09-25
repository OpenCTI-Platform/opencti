import { map } from 'ramda';
import { filesListing } from '../database/minio';
import { buildPagination } from '../database/utils';

const filesResolvers = {
  Query: {
    files: async (_, { category, entityId, first }) => {
      const files = await filesListing(category, entityId);
      const fileNodes = map(f => ({ node: f }), files);
      return buildPagination(first, 0, fileNodes, files.length);
    }
  }
};

export default filesResolvers;
