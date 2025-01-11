import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import ChannelEditionOverview from './ChannelEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import useHelper from '../../../../utils/hooks/useHelper';

const ChannelEditionContainer = (props) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const { handleClose, channel, open, controlledDial } = props;
  const { editContext } = channel;

  return (
    <Drawer
      title={t_i18n('Update a channel')}
      open={open}
      onClose={handleClose}
      variant={!isFABReplaced && open == null ? DrawerVariant.update : undefined}
      context={editContext}
      controlledDial={isFABReplaced ? controlledDial : undefined}
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
