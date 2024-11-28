import React, { FunctionComponent } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import ImportContent, { importContentQuery } from './ImportContent';
import Loader from '../../../../components/Loader';
import { ImportContentQuery } from './__generated__/ImportContentQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useHelper from '../../../../utils/hooks/useHelper';

interface ImportContentContainerProps {
  queryRef: PreloadedQuery<ImportContentQuery>;
}

const ImportContentContainer: FunctionComponent<ImportContentContainerProps> = ({ queryRef }) => {
  const data = usePreloadedQuery(importContentQuery, queryRef);
  const { isFeatureEnable } = useHelper();
  const isNewImportScreensEnabled = isFeatureEnable('NEW_IMPORT_SCREENS');
  return (
    <ImportContent
      connectorsImport={data.connectorsForImport}
      importFiles={data.importFiles}
      pendingFiles={data.pendingFiles}
      isNewImportScreensEnabled={isNewImportScreensEnabled}
    />
  );
};

const Import = () => {
  const queryRef = useQueryLoading<ImportContentQuery>(importContentQuery, {});
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader />}>
          <ImportContentContainer
            queryRef={queryRef}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default Import;
