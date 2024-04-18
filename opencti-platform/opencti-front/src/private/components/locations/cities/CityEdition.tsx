import React from 'react';
import CityEditionContainer, { cityEditionQuery } from './CityEditionContainer';
import { cityEditionOverviewFocus } from './CityEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { CityEditionContainerQuery } from './__generated__/CityEditionContainerQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const CityEdition = ({ cityId }: { cityId: string }) => {
  const [commit] = useApiMutation(cityEditionOverviewFocus);
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
