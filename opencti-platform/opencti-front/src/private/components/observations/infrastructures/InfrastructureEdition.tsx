import React from 'react';
import InfrastructureEditionContainer, { infrastructureEditionContainerQuery } from './InfrastructureEditionContainer';
import { infrastructureEditionOverviewFocus } from './InfrastructureEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { InfrastructureEditionContainerQuery } from './__generated__/InfrastructureEditionContainerQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const InfrastructureEdition = ({ infrastructureId }: { infrastructureId: string }) => {
  const [commit] = useApiMutation(infrastructureEditionOverviewFocus);
  const handleClose = () => {
    commit({
      variables: {
        id: infrastructureId,
        input: { focusOn: '' },
      },
    });
  };

  const queryRef = useQueryLoading<InfrastructureEditionContainerQuery>(
    infrastructureEditionContainerQuery,
    { id: infrastructureId },
  );

  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <InfrastructureEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default InfrastructureEdition;
