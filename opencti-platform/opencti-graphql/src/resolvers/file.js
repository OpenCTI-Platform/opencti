import { deleteFile, filesListing, loadFile } from '../database/file-storage';
import { askJobImport, uploadImport, uploadPending } from '../domain/file';
import { worksForSource } from '../domain/work';
import { stixCoreObjectImportDelete } from '../domain/stixCoreObject';
import { internalLoadById } from '../database/middleware';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { ENTITY_TYPE_USER } from '../schema/internalObject';

const fileResolvers = {
  Query: {
    file: (_, { id }, context) => loadFile(context, context.user, id),
    importFiles: (_, { first }, context) => filesListing(context, context.user, first, 'import/global/'),
    pendingFiles: (_, { first }, context) => filesListing(context, context.user, first, 'import/pending/'),
  },
  File: {
    works: (file, _, context) => worksForSource(context, context.user, file.id),
    metaData: (file, _, context) => {
      let { metaData } = file;
      if (metaData.entity_id) {
        metaData = { ...metaData, entity: internalLoadById(context, context.user, metaData.entity_id, { type: ABSTRACT_STIX_DOMAIN_OBJECT }) };
      }
      if (metaData.creator_id) {
        metaData = { ...metaData, creator: internalLoadById(context, context.user, metaData.creator_id, { type: ENTITY_TYPE_USER }) };
      }
      if (metaData.labels_text) {
        metaData = { ...metaData, labels: metaData.labels_text.split(';') };
      }
      return metaData;
    },
  },
  Mutation: {
    uploadImport: (_, { file }, context) => uploadImport(context, context.user, file),
    uploadPending: (_, { file, entityId, labels, errorOnExisting }, context) => uploadPending(context, context.user, file, entityId, labels, errorOnExisting),
    deleteImport: (_, { fileName }, context) => {
      // Imported file must be handle specifically
      // File deletion must publish a specific event
      // and update the updated_at field of the source entity
      if (fileName.startsWith('import') && !fileName.includes('global') && !fileName.includes('pending')) {
        return stixCoreObjectImportDelete(context, context.user, fileName);
      }
      // If not, a simple deletion is enough
      return deleteFile(context, context.user, fileName);
    },
    askJobImport: (_, args, context) => askJobImport(context, context.user, args),
  },
};

export default fileResolvers;
