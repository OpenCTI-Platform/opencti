import React, { FunctionComponent } from 'react';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { CaseRfiEditionContainerCaseQuery } from './__generated__/CaseRfiEditionContainerCaseQuery.graphql';
import CaseRfiEditionContainer, { caseRfiEditionQuery } from './CaseRfiEditionContainer';
import { caseRfiEditionOverviewFocus } from './CaseRfiEditionOverview';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const CaseRfiEdition: FunctionComponent<{ caseId: string }> = ({ caseId }) => {
  const [commit] = useApiMutation(caseRfiEditionOverviewFocus);
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
          fallback={<Loader variant={LoaderVariant.inline} />}
        >
          <CaseRfiEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
            controlledDial={EditEntityControlledDial}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default CaseRfiEdition;
