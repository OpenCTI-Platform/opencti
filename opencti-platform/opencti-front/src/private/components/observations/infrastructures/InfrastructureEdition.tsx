import React from 'react';
import { useMutation } from 'react-relay';
import InfrastructureEditionContainer, { infrastructureEditionContainerQuery } from './InfrastructureEditionContainer';
import { infrastructureEditionOverviewFocus } from './InfrastructureEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { InfrastructureEditionContainerQuery } from './__generated__/InfrastructureEditionContainerQuery.graphql';

const InfrastructureEdition = ({ infrastructureId }: { infrastructureId: string }) => {
  const [commit] = useMutation(infrastructureEditionOverviewFocus);
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
