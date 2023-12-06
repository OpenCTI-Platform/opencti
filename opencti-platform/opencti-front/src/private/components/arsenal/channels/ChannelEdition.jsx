import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import { Button } from '@mui/material';
import { Create } from '@mui/icons-material';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ChannelEditionContainer from './ChannelEditionContainer';
import { channelEditionOverviewFocus } from './ChannelEditionOverview';
import Loader from '../../../../components/Loader';

export const channelEditionQuery = graphql`
  query ChannelEditionContainerQuery($id: String!) {
    channel(id: $id) {
      ...ChannelEditionContainer_channel
    }
  }
`;

class ChannelEdition extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    commitMutation({
      mutation: channelEditionOverviewFocus,
      variables: {
        id: this.props.channelId,
        input: { focusOn: '' },
      },
    });
    this.setState({ open: false });
  }

  render() {
    const { t, channelId } = this.props;
    return (
      <QueryRenderer
        query={channelEditionQuery}
        variables={{ id: channelId }}
        render={({ props }) => {
          if (props) {
            return (
              <ChannelEditionContainer
                channel={props.channel}
                handleClose={this.handleClose.bind(this)}
                controlledDial={({ onOpen }) => (
                  <Button
                    style={{
                      marginLeft: '3px',
                      fontSize: 'small',
                    }}
                    variant='outlined'
                    onClick={onOpen}
                  >
                    {t('Edit')} <Create />
                  </Button>
                )}
              />
            );
          }
          return <Loader variant="inElement" />;
        }}
      />
    );
  }
}

ChannelEdition.propTypes = {
  channelId: PropTypes.string,
  me: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
)(ChannelEdition);
