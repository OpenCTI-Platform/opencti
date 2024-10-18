import React from 'react';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import ThreatActorIndividualEditionContainer, { ThreatActorIndividualEditionQuery } from './ThreatActorIndividualEditionContainer';
import { ThreatActorIndividualEditionOverviewFocusMutation } from './__generated__/ThreatActorIndividualEditionOverviewFocusMutation.graphql';
import { ThreatActorIndividualEditionContainerQuery } from './__generated__/ThreatActorIndividualEditionContainerQuery.graphql';
import { ThreatActorIndividualEditionOverviewFocus } from './ThreatActorIndividualEditionOverview';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

const ThreatActorIndividualEdition = ({
  threatActorIndividualId,
}: {
  threatActorIndividualId: string;
}) => {
  const [commit] = useApiMutation<ThreatActorIndividualEditionOverviewFocusMutation>(
    ThreatActorIndividualEditionOverviewFocus,
  );
  const handleClose = () => {
    commit({
      variables: {
        id: threatActorIndividualId,
        input: { focusOn: '' },
      },
    });
  };
  const queryRef = useQueryLoading<ThreatActorIndividualEditionContainerQuery>(
    ThreatActorIndividualEditionQuery,
    { id: threatActorIndividualId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inline} />}>
          <ThreatActorIndividualEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
            controlledDial={EditEntityControlledDial}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default ThreatActorIndividualEdition;
