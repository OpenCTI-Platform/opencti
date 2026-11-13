import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerControlledDialType } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import ProcedureEditionOverview from './ProcedureEditionOverview';
import { ProcedureEditionContainerQuery } from './__generated__/ProcedureEditionContainerQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

export const procedureEditionQuery = graphql`
  query ProcedureEditionContainerQuery($id: String!) {
    procedure(id: $id) {
      ...ProcedureEditionOverview_procedure
      editContext {
        name
        focusOn
      }
    }
  }
`;

interface ProcedureEditionContainerProps {
  queryRef: PreloadedQuery<ProcedureEditionContainerQuery>;
  handleClose: () => void;
  open?: boolean;
  controlledDial?: DrawerControlledDialType;
}

const ProcedureEditionContainer: FunctionComponent<ProcedureEditionContainerProps> = ({
  queryRef,
  handleClose,
  open,
  controlledDial,
}) => {
  const { t_i18n } = useFormatter();
  const { procedure } = usePreloadedQuery(procedureEditionQuery, queryRef);
  const enableReferences = useIsEnforceReference('Procedure');

  if (procedure) {
    return (
      <Drawer
        title={t_i18n('Update a procedure')}
        context={procedure.editContext}
        onClose={handleClose}
        open={open}
        controlledDial={controlledDial}
      >
        {({ onClose }) => (
          <ProcedureEditionOverview
            data={procedure}
            enableReferences={enableReferences}
            context={procedure.editContext}
            handleClose={onClose}
          />
        )}
      </Drawer>
    );
  }

  return <Loader variant={LoaderVariant.inline} />;
};

export default ProcedureEditionContainer;
