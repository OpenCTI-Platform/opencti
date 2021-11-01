import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Fab from '@material-ui/core/Fab';
import { Edit } from '@material-ui/icons';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer as QR, commitMutation as CM } from 'react-relay';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
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
  query DeviceEditionContainerQuery($id: String!) {
    threatActor(id: $id) {
      ...DeviceEditionContainer_device
    }
  }
`;

export const deviceEditionDarkLightQuery = graphql`
  query DeviceEditionContainerDarkLightQuery($id: ID!) {
    computingDeviceAsset(id: $id) {
      id
      name
      installed_operating_system {
        name
      }
      asset_id
      network_id
      description
      locations {
        description
      }
      version
      vendor_name
      asset_tag
      asset_type
      serial_number
      release_date
      # operational_status
      installed_software {
        name
      }
      connected_to_network {
        name
      }
      uri
      model
      mac_address
      fqdn
      baseline_configuration_name
      bios_id
      is_scanned
      hostname
      default_gateway
      motherboard_id
      installation_id
      netbios_name
      is_virtual
      is_publicly_accessible
      installed_hardware {
        name
        uri
      }
    }
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
      classes,
      deviceId,
      open,
      history,
    } = this.props;
    return (
      <div>
        {/* <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Edit"
          className={classes.editButton}
        >
          <Edit />
        </Fab> */}
        {/* <Drawer
          open={this.state.open}
          anchor="right"
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        > */}
        <div>
        <QR
          environment={environmentDarkLight}
          query={deviceEditionDarkLightQuery}
          variables={{ id: deviceId }}
          render={({ error, props }) => {
            console.log(`DeviceEditionDarkLightQuery Error ${error} OR Props ${JSON.stringify(props)}`);
            if (props) {
              return (
                <DeviceEditionContainer
                  device={props.computingDeviceAsset}
                  // enableReferences={props.settings.platform_enable_reference?.includes(
                    //   'Device',
                    // )}
                  history={history}
                  handleClose={this.handleClose.bind(this)}
                />
              );
            }
            return <Loader variant="inElement" />;
          }}
        />
          {/* <QueryRenderer
            query={deviceEditionQuery}
            variables={{ id: deviceId }}
            render={({ props }) => {
              if (props) {
                return (
                  <DeviceEditionContainer
                    device={props.threatActor}
                    // enableReferences={props.settings.platform_enable_reference?.includes(
                    //   'Device',
                    // )}
                    handleClose={this.handleClose.bind(this)}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          /> */}
        {/* </Drawer> */}
        </div>
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
