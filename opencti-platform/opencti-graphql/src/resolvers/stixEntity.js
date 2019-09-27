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
    uploadFile: (_, { input }, { user }) => uploadFile(input, user),
    deleteFile: (_, { fileName }, { user }) => deleteFile(fileName, user)
  }
};

export default stixEntityResolvers;
