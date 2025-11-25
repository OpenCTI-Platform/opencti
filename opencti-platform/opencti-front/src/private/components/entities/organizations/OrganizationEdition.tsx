import React from 'react';
import { OrganizationEditionContainerQuery } from '@components/entities/organizations/__generated__/OrganizationEditionContainerQuery.graphql';
import OrganizationEditionContainer, { organizationEditionQuery } from './OrganizationEditionContainer';
import { organizationEditionOverviewFocus } from './OrganizationEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

interface OrganizationEditionProps {
  organizationId: string
}

const OrganizationEdition = ({ organizationId }: OrganizationEditionProps) => {
  const [commit] = useApiMutation(organizationEditionOverviewFocus);

  const handleClose = () => {
    commit({
      variables: {
        id: organizationId,
        input: { focusOn: '' },
      },
    });
  };
  const queryRef = useQueryLoading<OrganizationEditionContainerQuery>(
    organizationEditionQuery,
    { id: organizationId },
  );

  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inline} />}
        >
          <OrganizationEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
            controlledDial={EditEntityControlledDial}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default OrganizationEdition;
