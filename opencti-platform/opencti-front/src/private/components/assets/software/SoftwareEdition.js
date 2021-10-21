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
import SoftwareEditionContainer from './SoftwareEditionContainer';
import { softwareEditionOverviewFocus } from './SoftwareEditionOverview';
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

export const softwareEditionQuery = graphql`
  query SoftwareEditionContainerQuery($id: String!) {
    campaign(id: $id) {
      ...SoftwareEditionContainer_software
    }
    settings {
      platform_enable_reference
    }
  }
`;

export const softwareEditionDarkLightQuery = graphql`
  query SoftwareEditionContainerDarkLightQuery($id: ID!) {
    softwareAsset(id: $id) {
      id
      name
      asset_id
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
      operational_status
      software_identifier
      license_key
      cpe_identifier
      patch_level
      installation_id
      implementation_point
    }
  }
`;

class SoftwareEdition extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    commitMutation({
      mutation: softwareEditionOverviewFocus,
      variables: {
        id: this.props.softwareId,
        input: { focusOn: '' },
      },
    });
    this.setState({ open: false });
  }

  render() {
    const {
      classes,
      softwareId,
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
        </Fab>
        <Drawer
          open={this.state.open}
          anchor="right"
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        > */}
          <QR
            environment={environmentDarkLight}
            query={softwareEditionDarkLightQuery}
            variables={{ id: softwareId }}
            render={({ props }) => {
              console.log(`SoftwareEditionDarkLightQuery OR Props ${JSON.stringify(props)}`);
              if (props) {
                return (
                  <SoftwareEditionContainer
                    software={props.softwareAsset}
                    // enableReferences={props.settings.platform_enable_reference?.includes(
                    //   'Software',
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
            query={softwareEditionQuery}
            variables={{ id: softwareId }}
            render={({ props }) => {
              if (props) {
                return (
                  <SoftwareEditionContainer
                    software={props.software}
                    enableReferences={props.settings.platform_enable_reference?.includes(
                      'Software',
                    )}
                    handleClose={this.handleClose.bind(this)}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          /> */}
        {/* </Drawer> */}
      </div>
    );
  }
}

SoftwareEdition.propTypes = {
  softwareId: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(SoftwareEdition);
