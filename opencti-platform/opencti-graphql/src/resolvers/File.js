import { deleteFile, filesListing } from '../database/minio';
import { askJobImport, uploadImport } from '../domain/file';
import { loadFileWorks } from '../domain/work';

const fileResolvers = {
  Query: {
    importFiles: (entity, { first }) => filesListing(first, 'import')
  },
  File: {
    jobs: file => loadFileWorks(file.id)
  },
  Mutation: {
    uploadImport: (_, { file }, { user }) => uploadImport(file, user),
    deleteImport: (_, { fileName }, { user }) => deleteFile(fileName, user),
    askJobImport: (_, { fileName }, { user }) => askJobImport(fileName, user)
  }
};

export default fileResolvers;
