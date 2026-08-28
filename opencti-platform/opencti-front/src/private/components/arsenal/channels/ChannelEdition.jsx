import React from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import ChannelEditionContainer from './ChannelEditionContainer';
import { channelEditionOverviewFocus } from './ChannelEditionOverview';
import Loader from '../../../../components/Loader';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

export const channelEditionQuery = graphql`
  query ChannelEditionContainerQuery($id: String!) {
    channel(id: $id) {
      ...ChannelEditionContainer_channel
    }
  }
`;

const ChannelEdition = (props) => {
  const handleClose = () => {
    commitMutation({
      mutation: channelEditionOverviewFocus,
      variables: {
        id: props.channelId,
        input: { focusOn: '' },
      },
    });
  };

  const { channelId } = props;
  return (
    <QueryRenderer
      query={channelEditionQuery}
      variables={{ id: channelId }}
      render={({ props }) => {
        if (props) {
          return (
            <ChannelEditionContainer
              channel={props.channel}
              handleClose={handleClose}
              controlledDial={EditEntityControlledDial}
            />
          );
        }
        return <Loader variant="inline" />;
      }}
    />
  );
};

ChannelEdition.propTypes = {
  channelId: PropTypes.string,
  me: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
};

export default ChannelEdition;
