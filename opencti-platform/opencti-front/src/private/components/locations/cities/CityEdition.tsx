import React, { FunctionComponent } from 'react';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import CityEditionContainer, { cityEditionQuery } from './CityEditionContainer';
import { cityEditionOverviewFocus } from './CityEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { CityEditionContainerQuery } from './__generated__/CityEditionContainerQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

const CityEdition: FunctionComponent<{ cityId: string }> = ({ cityId }) => {
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
          fallback={<Loader variant={LoaderVariant.inline} />}
        >
          <CityEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
            controlledDial={EditEntityControlledDial}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default CityEdition;
