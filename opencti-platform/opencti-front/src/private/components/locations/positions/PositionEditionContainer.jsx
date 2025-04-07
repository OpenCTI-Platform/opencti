import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import PositionEditionOverview from './PositionEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer from '../../common/drawer/Drawer';

const PositionEditionContainer = (props) => {
  const { t_i18n } = useFormatter();
  const { handleClose, position, open, controlledDial } = props;
  const { editContext } = position;
  return (
    <Drawer
      title={t_i18n('Update a position')}
      open={open}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
    >
      <>
        <PositionEditionOverview
          position={position}
          enableReferences={useIsEnforceReference('Position')}
          context={editContext}
          handleClose={handleClose}
        />
      </>
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
