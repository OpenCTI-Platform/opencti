import { paginatedForPathWithEnrichment } from '../../modules/internal/document/document-domain';
import { elSearchFiles } from '../../database/file-search';

export const resolveFiles = async (context, user, stixCoreObject) => {
  const opts = {
    first: 1,
    prefixMimeTypes: undefined,
    entity_id: stixCoreObject.id,
    entity_type: stixCoreObject.entity_type
  };
  const importFiles = await paginatedForPathWithEnrichment(context, user, `import/${stixCoreObject.entity_type}/${stixCoreObject.id}`, stixCoreObject.id, opts);
  const fileIds = importFiles.edges.map((n) => n.node.id);
  if (fileIds.length === 0) {
    return [];
  }
  const files = await elSearchFiles(context, user, {
    first: 1,
    fileIds,
    connectionFormat: false,
    excludeFields: [],
    includeContent: true
  });
  return files;
};
