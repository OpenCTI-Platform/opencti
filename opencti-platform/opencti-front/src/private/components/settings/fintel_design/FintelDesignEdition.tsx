import React from 'react';
import FintelDesignEditionContainer, { fintelDesignEditionQuery } from '@components/settings/fintel_design/FintelDesignEditionContainer';
import { fintelDesignEditionOverviewFocus } from '@components/settings/fintel_design/FintelDesignEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { FintelDesignEditionContainerQuery } from './__generated__/FintelDesignEditionContainerQuery.graphql';
import { FintelDesignEditionOverviewFocusMutation } from './__generated__/FintelDesignEditionOverviewFocusMutation.graphql';

const FintelDesignEdition = ({
  fintelDesignId,
}: {
  fintelDesignId: string;
}) => {
  const [commit] = useApiMutation<FintelDesignEditionOverviewFocusMutation>(
    fintelDesignEditionOverviewFocus,
  );
  const handleClose = () => {
    commit({
      variables: {
        id: fintelDesignId,
        input: { focusOn: '' },
      },
    });
  };
  const queryRef = useQueryLoading<FintelDesignEditionContainerQuery>(
    fintelDesignEditionQuery,
    { id: fintelDesignId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inline} />}>
          <FintelDesignEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
            controlledDial={EditEntityControlledDial}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default FintelDesignEdition;
