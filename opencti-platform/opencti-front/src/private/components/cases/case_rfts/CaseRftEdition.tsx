import React, { FunctionComponent } from 'react';
import { useMutation } from 'react-relay';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { CaseRftEditionContainerCaseQuery } from './__generated__/CaseRftEditionContainerCaseQuery.graphql';
import CaseRftEditionContainer, { caseRftEditionQuery } from './CaseRftEditionContainer';
import { caseRftEditionOverviewFocus } from './CaseRftEditionOverview';

const CaseRftEdition: FunctionComponent<{ caseId: string }> = ({ caseId }) => {
  const [commit] = useMutation(caseRftEditionOverviewFocus);
  const handleClose = () => {
    commit({
      variables: {
        id: caseId,
        input: { focusOn: '' },
      },
    });
  };
  const queryRef = useQueryLoading<CaseRftEditionContainerCaseQuery>(
    caseRftEditionQuery,
    { id: caseId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <CaseRftEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default CaseRftEdition;
