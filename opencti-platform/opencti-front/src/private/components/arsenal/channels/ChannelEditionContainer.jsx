import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import ChannelEditionOverview from './ChannelEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer from '../../common/drawer/Drawer';
import ChannelDelete from './ChannelDelete';

const ChannelEditionContainer = (props) => {
  const { t_i18n } = useFormatter();

  const { handleClose, channel, open, controlledDial } = props;
  const { editContext } = channel;

  return (
    <Drawer
      title={t_i18n('Update a channel')}
      open={open}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
    >
      <>
        <ChannelEditionOverview
          channel={channel}
          enableReferences={useIsEnforceReference('Channel')}
          context={editContext}
          handleClose={handleClose}
        />
        {!useIsEnforceReference('Channel')
          && <ChannelDelete id={channel.id} />
        }
      </>
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
