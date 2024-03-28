import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import EditEntityControlledDial from '../../common/menus/EditEntityControlledDial';
import { useFormatter } from '../../../../components/i18n';
import OpinionEditionOverview from './OpinionEditionOverview';
import Drawer from '../../common/drawer/Drawer';

const OpinionEditionContainer = (props) => {
  const { t_i18n } = useFormatter();

  const { handleClose, opinion, open } = props;
  const { editContext } = opinion;

  return (
    <Drawer
      title={t_i18n('Update a opinions')}
      open={open}
      onClose={handleClose}
      context={editContext}
      controlledDial={EditEntityControlledDial(true)}
    >
      <OpinionEditionOverview
        opinion={opinion}
        context={editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

const OpinionEditionFragment = createFragmentContainer(
  OpinionEditionContainer,
  {
    opinion: graphql`
      fragment OpinionEditionContainer_opinion on Opinion {
        id
        ...OpinionEditionOverview_opinion
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default OpinionEditionFragment;
