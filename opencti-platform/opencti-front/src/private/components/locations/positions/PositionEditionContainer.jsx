import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import PositionEditionOverview from './PositionEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';

const PositionEditionContainer = (props) => {
  const { t } = useFormatter();
  const { handleClose, position, open } = props;
  const { editContext } = position;
  return (
    <Drawer
      title={t('Update a position')}
      open={open}
      onClose={handleClose}
      variant={open == null ? DrawerVariant.update : undefined}
      context={editContext}
    >
      <PositionEditionOverview
        position={position}
        enableReferences={useIsEnforceReference('Position')}
        context={editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

const PositionEditionFragment = createFragmentContainer(
  PositionEditionContainer,
  {
    position: graphql`
      fragment PositionEditionContainer_position on Position {
        id
        ...PositionEditionOverview_position
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default PositionEditionFragment;
