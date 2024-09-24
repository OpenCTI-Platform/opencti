import React from 'react';
import InfrastructureEditionContainer, { infrastructureEditionContainerQuery } from './InfrastructureEditionContainer';
import { infrastructureEditionOverviewFocus } from './InfrastructureEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { InfrastructureEditionContainerQuery } from './__generated__/InfrastructureEditionContainerQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

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
          fallback={<Loader variant={LoaderVariant.inline} />}
        >
          <InfrastructureEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
            controlledDial={EditEntityControlledDial}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default InfrastructureEdition;
