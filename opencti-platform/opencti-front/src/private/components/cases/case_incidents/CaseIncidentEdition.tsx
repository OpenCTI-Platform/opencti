import React, { FunctionComponent } from 'react';
import { useMutation } from 'react-relay';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { CaseIncidentEditionContainerCaseQuery } from './__generated__/CaseIncidentEditionContainerCaseQuery.graphql';
import CaseIncidentEditionContainer, { caseIncidentEditionQuery } from './CaseIncidentEditionContainer';
import { caseIncidentEditionOverviewFocus } from './CaseIncidentEditionOverview';

const CaseIncidentEdition: FunctionComponent<{ caseId: string }> = ({ caseId }) => {
  const [commit] = useMutation(caseIncidentEditionOverviewFocus);
  const handleClose = () => {
    commit({
      variables: {
        id: caseId,
        input: { focusOn: '' },
      },
    });
  };
  const queryRef = useQueryLoading<CaseIncidentEditionContainerCaseQuery>(
    caseIncidentEditionQuery,
    { id: caseId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <CaseIncidentEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default CaseIncidentEdition;
