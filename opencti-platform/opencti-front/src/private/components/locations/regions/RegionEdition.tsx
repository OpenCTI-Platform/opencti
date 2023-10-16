import React from 'react';
import { useMutation } from 'react-relay';
import RegionEditionContainer, { regionEditionQuery } from './RegionEditionContainer';
import { regionEditionOverviewFocus } from './RegionEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { RegionEditionContainerQuery } from './__generated__/RegionEditionContainerQuery.graphql';

const RegionEdition = ({ regionId }: { regionId: string }) => {
  const [commit] = useMutation(regionEditionOverviewFocus);
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
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <RegionEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default RegionEdition;
