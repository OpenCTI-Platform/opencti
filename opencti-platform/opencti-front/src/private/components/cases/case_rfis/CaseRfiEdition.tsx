import React, { FunctionComponent } from 'react';
import { useMutation } from 'react-relay';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { CaseRfiEditionContainerCaseQuery } from './__generated__/CaseRfiEditionContainerCaseQuery.graphql';
import CaseRfiEditionContainer, { caseRfiEditionQuery } from './CaseRfiEditionContainer';
import { caseRfiEditionOverviewFocus } from './CaseRfiEditionOverview';

const CaseRfiEdition: FunctionComponent<{ caseId: string }> = ({ caseId }) => {
  const [commit] = useMutation(caseRfiEditionOverviewFocus);
  const handleClose = () => {
    commit({
      variables: {
        id: caseId,
        input: { focusOn: '' },
      },
    });
  };
  const queryRef = useQueryLoading<CaseRfiEditionContainerCaseQuery>(
    caseRfiEditionQuery,
    { id: caseId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <CaseRfiEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default CaseRfiEdition;
