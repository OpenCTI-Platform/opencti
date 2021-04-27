import { deleteFile, filesListing } from '../database/minio';
import { askJobImport, uploadImport } from '../domain/file';
import { worksForSource } from '../domain/work';

const fileResolvers = {
  Query: {
    importFiles: (entity, { first }, { user }) => filesListing(user, first, 'import/global/'),
  },
  File: {
    works: (file, _, { user }) => worksForSource(user, file.id),
  },
  Mutation: {
    uploadImport: (_, { file }, { user }) => uploadImport(user, file),
    deleteImport: (_, { fileName }, { user }) => deleteFile(user, fileName),
    askJobImport: (_, args, { user }) => askJobImport(user, args),
  },
};

export default fileResolvers;
