import React from 'react';
import { useMutation } from 'react-relay';
import IncidentEditionContainer, { IncidentEditionQuery } from './IncidentEditionContainer';
import { incidentEditionOverviewFocus } from './IncidentEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { IncidentEditionContainerQuery } from './__generated__/IncidentEditionContainerQuery.graphql';

const IncidentEdition = ({ incidentId }: { incidentId: string }) => {
  const [commit] = useMutation(incidentEditionOverviewFocus);
  const handleClose = () => {
    commit({
      variables: {
        id: incidentId,
        input: { focusOn: '' },
      },
    });
  };

  const queryRef = useQueryLoading<IncidentEditionContainerQuery>(
    IncidentEditionQuery,
    { id: incidentId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <IncidentEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default IncidentEdition;
