/* eslint-disable */
/* refactor */
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
import NetworkEditionContainer from './NetworkEditionContainer';
import { networkEditionOverviewFocus } from './NetworkEditionOverview';
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

export const networkEditionQuery = graphql`
  query NetworkEditionContainerQuery($id: String!) {
    intrusionSet(id: $id) {
      ...NetworkEditionContainer_network
    }
    settings {
      platform_enable_reference
    }
  }
`;

// export const networkEditionDarkLightQuery = graphql`
//   query NetworkEditionContainerDarkLightQuery($id: ID!) {
//     networkAsset(id: $id) {
//       id
//       name
//       asset_id
//       fqdn
//       network_id
//       description
//       locations {
//         description
//       }
//       version
//       vendor_name
//       asset_tag
//       asset_type
//       serial_number
//       release_date
//       operational_status
//     }
//   }
// `;

export const networkEditionDarkLightQuery = graphql`
  query NetworkEditionContainerDarkLightQuery($id: ID!) {
    networkAsset(id: $id) {
      id
      name
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
      network_name
      network_id
      # implementation_point
      # network_address_range {
      #   ending_ip_address{
      #     ... on IpV4Address {
      #       ip_address_value
      #     }
      #   }
      #   starting_ip_address{
      #     ... on IpV4Address {
      #       ip_address_value
      #     }
      #   }
      # }
    }
  }
`;

class NetworkEdition extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    commitMutation({
      mutation: networkEditionOverviewFocus,
      variables: {
        id: this.props.networkId,
        input: { focusOn: '' },
      },
    });
    this.setState({ open: false });
  }

  render() {
    const { classes, networkId, history } = this.props;
    return (
      <div>
        <QR
            environment={environmentDarkLight}
            query={networkEditionDarkLightQuery}
            variables={{ id: networkId }}
            render={({ props }) => {
              if (props) {
                return (
                  <NetworkEditionContainer
                    network={props.networkAsset}
                    // enableReferences={props.settings.platform_enable_reference?.includes(
                    //   'Network',
                    // )}
                    history={history}
                    handleClose={this.handleClose.bind(this)}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          />
        {/* <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Edit"
          className={classes.editButton}
        >
          <Edit />
        </Fab>
        <Drawer
          open={this.state.open}
          anchor="right"
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <QueryRenderer
            query={networkEditionQuery}
            variables={{ id: networkId }}
            render={({ props }) => {
              if (props) {
                return (
                  <NetworkEditionContainer
                    network={props.network}
                    enableReferences={props.settings.platform_enable_reference?.includes(
                      'Network',
                    )}
                    handleClose={this.handleClose.bind(this)}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          />
        </Drawer> */}
      </div>
    );
  }
}

NetworkEdition.propTypes = {
  networkId: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(NetworkEdition);
