import React, { FunctionComponent } from 'react';
import { ImportContentContainer_connectorsImport$data } from '@components/data/import/__generated__/ImportContentContainer_connectorsImport.graphql';
import ImportWorkbenchesContent, { importWorkbenchesContentQuery } from '@components/data/import/ImportWorkbenchesContent';
import { ImportWorkbenchesContentQuery } from '@components/data/import/__generated__/ImportWorkbenchesContentQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';

interface ImportWorkbenchesProps {
  connectors: ImportContentContainer_connectorsImport$data,
}

const ImportWorkbenches: FunctionComponent<ImportWorkbenchesProps> = ({
  connectors,
}) => {
  const queryRef = useQueryLoading<ImportWorkbenchesContentQuery>(
    importWorkbenchesContentQuery,
    {},
  );

  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader />}>
          <ImportWorkbenchesContent queryRef={queryRef} connectors={connectors} />
        </React.Suspense>
      )}
    </>
  );
};

export default ImportWorkbenches;
