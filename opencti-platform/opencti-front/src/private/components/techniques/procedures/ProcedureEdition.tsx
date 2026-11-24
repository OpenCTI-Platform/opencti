import React, { FunctionComponent } from 'react';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ProcedureEditionContainer, { procedureEditionQuery } from './ProcedureEditionContainer';
import { procedureEditionOverviewFocus } from './ProcedureEditionOverview';
import { ProcedureEditionContainerQuery } from './__generated__/ProcedureEditionContainerQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

const ProcedureEdition: FunctionComponent<{ procedureId: string }> = ({ procedureId }) => {
  const [commit] = useApiMutation(procedureEditionOverviewFocus);

  const handleClose = () => {
    commit({
      variables: {
        id: procedureId,
        input: { focusOn: '' },
      },
    });
  };

  const queryRef = useQueryLoading<ProcedureEditionContainerQuery>(
    procedureEditionQuery,
    { id: procedureId },
  );

  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inline} />}>
          <ProcedureEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
            controlledDial={EditEntityControlledDial}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default ProcedureEdition;
