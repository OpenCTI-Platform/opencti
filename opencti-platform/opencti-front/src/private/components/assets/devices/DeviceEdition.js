/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer as QR } from 'react-relay';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import DeviceEditionContainer from './DeviceEditionContainer';
import { deviceEditionOverviewFocus } from './DeviceEditionOverview';
import Loader from '../../../../components/Loader';

const styles = (theme) => ({
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
});

export const deviceEditionQuery = graphql`
  query DeviceEditionContainerQuery($id: ID!) {
    hardwareAsset(id: $id) {
      ...DeviceEditionContainer_device
    }
    # settings {
    #   platform_enable_reference
    # }
  }
`;

class DeviceEdition extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    commitMutation({
      mutation: deviceEditionOverviewFocus,
      variables: {
        id: this.props.deviceId,
        input: { focusOn: '' },
      },
    });
    this.setState({ open: false });
  }

  render() {
    const {
      deviceId,
      history,
    } = this.props;
    return (
      <div>
        <QR
          environment={environmentDarkLight}
          query={deviceEditionQuery}
          variables={{ id: deviceId }}
          render={({ error, props, retry }) => {
            if (props) {
              return (
                <DeviceEditionContainer
                  device={props.hardwareAsset}
                  // enableReferences={props.settings.platform_enable_reference?.includes(
                  //   'Device',
                  // )}
                  history={history}
                  refreshQuery={retry}
                  handleClose={this.handleClose.bind(this)}
                />
              );
            }
            return <Loader variant="inElement" />;
          }}
        />
      </div>
    );
  }
}

DeviceEdition.propTypes = {
  deviceId: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(DeviceEdition);
