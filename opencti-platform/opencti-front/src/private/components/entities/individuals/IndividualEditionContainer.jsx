import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import IndividualEditionOverview from './IndividualEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer from '../../common/drawer/Drawer';
import { useEntityTypeDisplayName } from '../../../../utils/hooks/useEntityTypeDisplayName';

const IndividualEditionContainer = (props) => {
  const { t_i18n } = useFormatter();
  const entityTypeDisplayName = useEntityTypeDisplayName();

  const { handleClose, individual, open, controlledDial } = props;
  const { editContext } = individual;

  return (
    <Drawer
      title={t_i18n('', { id: 'Update ...', values: { entity_type: entityTypeDisplayName('Individual') } })}
      open={open}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
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
