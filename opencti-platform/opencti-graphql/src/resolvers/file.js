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
    uploadImport: (_, { file }, { user }) => uploadImport(file, user),
    deleteImport: (_, { fileName }, { user }) => deleteFile(fileName, user),
    askJobImport: (_, { fileName, context }, { user }) => askJobImport(fileName, context, user),
  },
};

export default fileResolvers;
