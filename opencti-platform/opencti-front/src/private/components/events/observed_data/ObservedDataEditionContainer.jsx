import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import ObservedDataEditionOverview from './ObservedDataEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer from '../../common/drawer/Drawer';

const ObservedDataEditionContainer = (props) => {
  const { t_i18n } = useFormatter();
  const { handleClose, observedData, open, controlledDial } = props;
  const { editContext } = observedData;

  return (
    <Drawer
      title={t_i18n('Update an observed data')}
      open={open}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
    >
      <ObservedDataEditionOverview
        observedData={observedData}
        enableReferences={useIsEnforceReference('Observed-Data')}
        context={editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

const ObservedDataEditionFragment = createFragmentContainer(
  ObservedDataEditionContainer,
  {
    observedData: graphql`
      fragment ObservedDataEditionContainer_observedData on ObservedData {
        id
        ...ObservedDataEditionOverview_observedData
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default ObservedDataEditionFragment;
