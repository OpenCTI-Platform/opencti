import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import ChannelEditionOverview from './ChannelEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';

const ChannelEditionContainer = (props) => {
  const { t } = useFormatter();

  const { handleClose, channel, open } = props;
  const { editContext } = channel;

  return (
    <Drawer
      title={t('Update a channel')}
      open={open}
      onClose={handleClose}
      variant={open == null ? DrawerVariant.update : undefined}
      context={editContext}
    >
      <ChannelEditionOverview
        channel={channel}
        enableReferences={useIsEnforceReference('Channel')}
        context={editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

const ChannelEditionFragment = createFragmentContainer(ChannelEditionContainer, {
  channel: graphql`
    fragment ChannelEditionContainer_channel on Channel {
      id
      ...ChannelEditionOverview_channel
      editContext {
        name
        focusOn
      }
    }
  `,
});

export default ChannelEditionFragment;
