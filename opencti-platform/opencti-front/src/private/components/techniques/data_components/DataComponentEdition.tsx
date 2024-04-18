import React, { FunctionComponent } from 'react';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import DataComponentEditionContainer, { dataComponentEditionQuery } from './DataComponentEditionContainer';
import { dataComponentEditionOverviewFocus } from './DataComponentEditionOverview';
import { DataComponentEditionContainerQuery } from './__generated__/DataComponentEditionContainerQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const DataComponentEdition: FunctionComponent<{ dataComponentId: string }> = ({
  dataComponentId,
}) => {
  const [commit] = useApiMutation(dataComponentEditionOverviewFocus);

  const handleClose = () => {
    commit({
      variables: {
        id: dataComponentId,
        input: { focusOn: '' },
      },
    });
  };

  const queryRef = useQueryLoading<DataComponentEditionContainerQuery>(
    dataComponentEditionQuery,
    { id: dataComponentId },
  );

  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <DataComponentEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default DataComponentEdition;
