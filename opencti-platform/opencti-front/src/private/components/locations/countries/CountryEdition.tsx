import React, { FunctionComponent } from 'react';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { CountryEditionContainerQuery } from './__generated__/CountryEditionContainerQuery.graphql';
import CountryEditionContainer, { countryEditionQuery } from './CountryEditionContainer';
import { countryEditionOverviewFocus } from './CountryEditionOverview';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const CountryEdition: FunctionComponent<{ countryId: string }> = ({ countryId }) => {
  const [commit] = useApiMutation(countryEditionOverviewFocus);
  const handleClose = () => {
    commit({
      variables: {
        id: countryId,
        input: { focusOn: '' },
      },
    });
  };
  const queryRef = useQueryLoading<CountryEditionContainerQuery>(
    countryEditionQuery,
    { id: countryId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inline} />}
        >
          <CountryEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
            controlledDial={EditEntityControlledDial}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default CountryEdition;
