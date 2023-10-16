import React from 'react';
import { useMutation } from 'react-relay';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import ThreatActorIndividualEditionContainer, { ThreatActorIndividualEditionQuery } from './ThreatActorIndividualEditionContainer';
import { ThreatActorIndividualEditionOverviewFocusMutation } from './__generated__/ThreatActorIndividualEditionOverviewFocusMutation.graphql';
import { ThreatActorIndividualEditionContainerQuery } from './__generated__/ThreatActorIndividualEditionContainerQuery.graphql';
import { ThreatActorIndividualEditionOverviewFocus } from './ThreatActorIndividualEditionOverview';

const ThreatActorIndividualEdition = ({ threatActorIndividualId }: { threatActorIndividualId: string }) => {
  const [commit] = useMutation<ThreatActorIndividualEditionOverviewFocusMutation>(ThreatActorIndividualEditionOverviewFocus);
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
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <ThreatActorIndividualEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default ThreatActorIndividualEdition;
