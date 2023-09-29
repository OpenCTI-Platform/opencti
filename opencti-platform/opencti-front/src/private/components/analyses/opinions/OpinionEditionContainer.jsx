import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import OpinionEditionOverview from './OpinionEditionOverview';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';

const OpinionEditionContainer = (props) => {
  const { t } = useFormatter();

  const { handleClose, opinion, open } = props;
  const { editContext } = opinion;

  return (
    <Drawer
      title={t('Update a opinions')}
      open={open}
      onClose={handleClose}
      variant={open == null ? DrawerVariant.update : undefined}
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
