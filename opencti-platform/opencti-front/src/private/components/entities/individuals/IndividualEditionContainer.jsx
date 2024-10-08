import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import IndividualEditionOverview from './IndividualEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import useHelper from '../../../../utils/hooks/useHelper';

const IndividualEditionContainer = (props) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const FABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const { handleClose, individual, open, controlledDial } = props;
  const { editContext } = individual;

  return (
    <Drawer
      title={t_i18n('Update a individual')}
      open={open}
      onClose={handleClose}
      variant={!FABReplaced && open == null ? DrawerVariant.update : undefined}
      context={editContext}
      controlledDial={FABReplaced ? controlledDial : undefined}
    >
      <IndividualEditionOverview
        individual={individual}
        enableReferences={useIsEnforceReference('Individual')}
        context={editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

const IndividualEditionFragment = createFragmentContainer(
  IndividualEditionContainer,
  {
    individual: graphql`
      fragment IndividualEditionContainer_individual on Individual {
        id
        ...IndividualEditionOverview_individual
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default IndividualEditionFragment;
