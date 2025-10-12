import React, { FunctionComponent } from 'react';
import SecurityCoverageEditionContainer, { securityCoverageEditionContainerQuery } from './SecurityCoverageEditionContainer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { SecurityCoverageEditionContainerQuery } from './__generated__/SecurityCoverageEditionContainerQuery.graphql';
import { securityCoverageEditionOverviewFocus } from './SecurityCoverageEditionOverview';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

const SecurityCoverageEdition: FunctionComponent<{ securityCoverageId: string }> = ({ securityCoverageId }) => {
  const [commit] = useApiMutation(securityCoverageEditionOverviewFocus);

  const handleClose = () => {
    commit({
      variables: {
        id: securityCoverageId,
        input: { focusOn: '' },
      },
    });
  };

  const queryRef = useQueryLoading<SecurityCoverageEditionContainerQuery>(securityCoverageEditionContainerQuery, { id: securityCoverageId });

  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inline} />}
        >
          <SecurityCoverageEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
            controlledDial={EditEntityControlledDial}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default SecurityCoverageEdition;
