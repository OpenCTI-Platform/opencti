import React, { FunctionComponent } from 'react';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { CaseRftEditionContainerCaseQuery } from './__generated__/CaseRftEditionContainerCaseQuery.graphql';
import CaseRftEditionContainer, { caseRftEditionQuery } from './CaseRftEditionContainer';
import { caseRftEditionOverviewFocus } from './CaseRftEditionOverview';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const CaseRftEdition: FunctionComponent<{ caseId: string }> = ({ caseId }) => {
  const [commit] = useApiMutation(caseRftEditionOverviewFocus);
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
          fallback={<Loader variant={LoaderVariant.inline} />}
        >
          <CaseRftEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
            controlledDial={EditEntityControlledDial}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default CaseRftEdition;
