import { deleteFile, filesListing } from '../database/minio';
import { askJobImport, uploadImport } from '../domain/file';
import { loadFileWorks } from '../domain/work';

const fileResolvers = {
  Query: {
    importFiles: (entity, { first }) => filesListing(first, 'import'),
  },
  File: {
    works: (file) => loadFileWorks(file.id),
  },
  Mutation: {
    uploadImport: (_, { file }, { user }) => uploadImport(user, file),
    deleteImport: (_, { fileName }, { user }) => deleteFile(user, fileName),
    askJobImport: (_, { fileName, context }, { user }) => askJobImport(user, fileName, context),
  },
};

export default fileResolvers;
