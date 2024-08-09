import React from 'react';
import { importContentQuery } from './ImportContent';
import Loader from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import ImportContentContainer from './ImportContentContainer';
import { ImportContentQuery } from './__generated__/ImportContentQuery.graphql';

const Import = ({ tab }: { tab: string }) => {
  const queryRef = useQueryLoading<ImportContentQuery>(importContentQuery, {});
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader/>}>
          <ImportContentContainer
            tab={tab}
            queryRef={queryRef}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default Import;
