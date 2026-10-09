import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import OpinionEditionOverview from './OpinionEditionOverview';
import Drawer from '../../common/drawer/Drawer';

const OpinionEditionContainer = (props) => {
  const { t_i18n } = useFormatter();

  const { handleClose, opinion, open, controlledDial } = props;
  const { editContext } = opinion;

  return (
    <Drawer
      title={t_i18n('Update an opinion')}
      open={open}
      onClose={handleClose}
      controlledDial={controlledDial}
      context={editContext}
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
