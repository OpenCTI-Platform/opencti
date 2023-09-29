import React from 'react';
import { useMutation } from 'react-relay';
import CityEditionContainer, { cityEditionQuery } from './CityEditionContainer';
import { cityEditionOverviewFocus } from './CityEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { CityEditionContainerQuery } from './__generated__/CityEditionContainerQuery.graphql';

const CityEdition = ({ cityId }: { cityId: string }) => {
  const [commit] = useMutation(cityEditionOverviewFocus);
  const handleClose = () => {
    commit({
      variables: {
        id: cityId,
        input: { focusOn: '' },
      },
    });
  };
  const queryRef = useQueryLoading<CityEditionContainerQuery>(
    cityEditionQuery,
    { id: cityId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <CityEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default CityEdition;
