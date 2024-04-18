import React from 'react';
import AdministrativeAreaEditionContainer, { administrativeAreaEditionQuery } from './AdministrativeAreaEditionContainer';
import { administrativeAreaEditionOverviewFocus } from './AdministrativeAreaEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { AdministrativeAreaEditionContainerQuery } from './__generated__/AdministrativeAreaEditionContainerQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const AdministrativeAreaEdition = ({
  administrativeAreaId,
}: {
  administrativeAreaId: string;
}) => {
  const [commit] = useApiMutation(administrativeAreaEditionOverviewFocus);
  const handleClose = () => {
    commit({
      variables: {
        id: administrativeAreaId,
        input: { focusOn: '' },
      },
    });
  };
  const queryRef = useQueryLoading<AdministrativeAreaEditionContainerQuery>(
    administrativeAreaEditionQuery,
    { id: administrativeAreaId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <AdministrativeAreaEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default AdministrativeAreaEdition;
