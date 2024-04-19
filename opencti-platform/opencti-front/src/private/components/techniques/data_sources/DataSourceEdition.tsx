import React from 'react';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { dataSourceEditionOverviewFocus } from './DataSourceEditionOverview';
import DataSourceEditionContainer, { dataSourceEditionQuery } from './DataSourceEditionContainer';
import { DataSourceEditionContainerQuery } from './__generated__/DataSourceEditionContainerQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const DataSourceEdition = ({ dataSourceId }: { dataSourceId: string }) => {
  const [commit] = useApiMutation(dataSourceEditionOverviewFocus);

  const handleClose = () => {
    commit({
      variables: {
        id: dataSourceId,
        input: { focusOn: '' },
      },
    });
  };

  const queryRef = useQueryLoading<DataSourceEditionContainerQuery>(
    dataSourceEditionQuery,
    { id: dataSourceId },
  );

  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <DataSourceEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default DataSourceEdition;
