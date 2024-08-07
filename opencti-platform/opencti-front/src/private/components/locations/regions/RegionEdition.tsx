import React, { FunctionComponent } from 'react';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { RegionEditionContainerQuery } from './__generated__/RegionEditionContainerQuery.graphql';
import RegionEditionContainer, { regionEditionQuery } from './RegionEditionContainer';
import { regionEditionOverviewFocus } from './RegionEditionOverview';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const RegionEdition: FunctionComponent<{ regionId: string }> = ({ regionId }) => {
  const [commit] = useApiMutation(regionEditionOverviewFocus);
  const handleClose = () => {
    commit({
      variables: {
        id: regionId,
        input: { focusOn: '' },
      },
    });
  };
  const queryRef = useQueryLoading<RegionEditionContainerQuery>(
    regionEditionQuery,
    { id: regionId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inline} />}
        >
          <RegionEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
            controlledDial={EditEntityControlledDial}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default RegionEdition;
