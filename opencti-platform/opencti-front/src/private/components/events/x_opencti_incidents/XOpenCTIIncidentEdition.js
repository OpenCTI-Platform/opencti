import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Fab from '@material-ui/core/Fab';
import { Edit } from '@material-ui/icons';
import graphql from 'babel-plugin-relay/macro';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import XOpenCTIIncidentEditionContainer from './XOpenCTIIncidentEditionContainer';
import { XOpenCTIIncidentEditionOverviewFocus } from './XOpenCTIIncidentEditionOverview';
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

export const XOpenCTIIncidentEditionQuery = graphql`
  query XOpenCTIIncidentEditionContainerQuery($id: String!) {
    xOpenCTIIncident(id: $id) {
      ...XOpenCTIIncidentEditionContainer_xOpenCTIIncident
    }
  }
`;

class XOpenCTIXOpenCTIIncidentEdition extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    commitMutation({
      mutation: XOpenCTIIncidentEditionOverviewFocus,
      variables: {
        id: this.props.xOpenCTIIncidentId,
        input: { focusOn: '' },
      },
    });
    this.setState({ open: false });
  }

  render() {
    const { classes, xOpenCTIIncidentId } = this.props;
    return (
      <div>
        <Fab
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
            query={XOpenCTIIncidentEditionQuery}
            variables={{ id: xOpenCTIIncidentId }}
            render={({ props }) => {
              if (props) {
                return (
                  <XOpenCTIIncidentEditionContainer
                    xOpenCTIIncident={props.xOpenCTIIncident}
                    handleClose={this.handleClose.bind(this)}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          />
        </Drawer>
      </div>
    );
  }
}

XOpenCTIXOpenCTIIncidentEdition.propTypes = {
  xOpenCTIIncidentId: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(XOpenCTIXOpenCTIIncidentEdition);
