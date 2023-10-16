import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import IndividualEditionOverview from './IndividualEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';

const IndividualEditionContainer = (props) => {
  const { t } = useFormatter();

  const { handleClose, individual, open } = props;
  const { editContext } = individual;

  return (
    <Drawer
      title={t('Update a individual')}
      open={open}
      onClose={handleClose}
      variant={open == null ? DrawerVariant.update : undefined}
      context={editContext}
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
