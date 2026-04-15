import { usePreloadedQuery } from 'react-relay';
import type { PreloadedQuery } from 'react-relay';
import { importFilesQuery } from './ImportFilesContext';
import type { ImportFilesContextQuery } from './__generated__/ImportFilesContextQuery.graphql';

/**
 * Thin wrapper around usePreloadedQuery for the ImportFilesContext query.
 *
 * Extracted into its own hook so tests can mock it without having to mock
 * 'react-relay' directly (which causes worker timeouts via vite-plugin-relay).
 */
const useImportFilesData = (queryRef: PreloadedQuery<ImportFilesContextQuery>) => {
  return usePreloadedQuery<ImportFilesContextQuery>(importFilesQuery, queryRef);
};

export default useImportFilesData;
