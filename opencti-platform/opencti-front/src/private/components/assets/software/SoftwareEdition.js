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
  query SoftwareEditionContainerQuery($id: ID!) {
    softwareAsset(id: $id) {
      ...SoftwareEditionContainer_software
    }
    # settings {
    #   platform_enable_reference
    # }
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
        <QR
          environment={environmentDarkLight}
          query={softwareEditionQuery}
          variables={{ id: softwareId }}
          render={({ props, retry }) => {
            if (props) {
              return (
                <SoftwareEditionContainer
                  software={props.softwareAsset}
                  // enableReferences={props.settings.platform_enable_reference?.includes(
                  //   'Software',
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
