import React, { FunctionComponent } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import ImportContent, { importContentQuery } from './ImportContent';
import Loader from '../../../../components/Loader';
import { ImportContentQuery } from './__generated__/ImportContentQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useHelper from '../../../../utils/hooks/useHelper';

interface ImportContentContainerProps {
  queryRef: PreloadedQuery<ImportContentQuery>;
  inDraftOverview: boolean;
}

const ImportContentContainer: FunctionComponent<ImportContentContainerProps> = ({ queryRef, inDraftOverview }) => {
  const data = usePreloadedQuery(importContentQuery, queryRef);
  const { isFeatureEnable } = useHelper();
  const isNewImportScreensEnabled = isFeatureEnable('NEW_IMPORT_SCREENS');
  return (
    <ImportContent
      connectorsImport={data.connectorsForImport}
      importFiles={data.importFiles}
      pendingFiles={data.pendingFiles}
      isNewImportScreensEnabled={isNewImportScreensEnabled}
      inDraftOverview={inDraftOverview}
    />
  );
};

const Import = ({ inDraftOverview = false }) => {
  const queryRef = useQueryLoading<ImportContentQuery>(importContentQuery, {});
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader />}>
          <ImportContentContainer
            inDraftOverview={inDraftOverview}
            queryRef={queryRef}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default Import;
