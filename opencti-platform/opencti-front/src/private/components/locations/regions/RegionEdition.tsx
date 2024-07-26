import React from 'react';
import RegionEditionContainer, { regionEditionQuery } from './RegionEditionContainer';
import { regionEditionOverviewFocus } from './RegionEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { RegionEditionContainerQuery } from './__generated__/RegionEditionContainerQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

const RegionEdition = ({ regionId }: { regionId: string }) => {
  const [commit] = useApiMutation(regionEditionOverviewFocus);
  const handleClose = () => {
    commit({
      variables: {
        id: regionId,
        input: { focusOn: '' },
      },
    });
  };
  const queryRef = useQueryLoading<RegionEditionContainerQuery>(
    regionEditionQuery,
    { id: regionId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inline} />}
        >
          <RegionEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
            controlledDial={EditEntityControlledDial}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default RegionEdition;
