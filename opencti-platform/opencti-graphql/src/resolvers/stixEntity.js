import { uploadFile } from '../domain/stixEntity';
import { deleteFile } from '../database/minio';

const stixEntityResolvers = {
  StixEntity: {
    // eslint-disable-next-line
    __resolveType(obj) {
      if (obj.observable_value) {
        return 'StixObservable';
      }
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) =>
          letter.toUpperCase()
        );
      }
      return 'Unknown';
    }
  },
  Mutation: {
    uploadFile: (_, { input }) => uploadFile(input),
    deleteFile: (_, { fileName }) => deleteFile(fileName)
  }
};

export default stixEntityResolvers;
