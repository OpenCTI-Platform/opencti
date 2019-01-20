import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Fab from '@material-ui/core/Fab';
import { Edit } from '@material-ui/icons';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../components/i18n';
import ReportEditionContainer from './ReportEditionContainer';
import { QueryRenderer } from '../../../relay/environment';

const styles = theme => ({
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

const reportEditionQuery = graphql`
  query ReportEditionContainerQuery($id: String!) {
    report(id: $id) {
      ...ReportEditionContainer_report
    }
    me {
      ...ReportEditionContainer_me
    }
  }
`;

class ReportEdition extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  render() {
    const { classes, reportId } = this.props;
    return (
      <div>
        <Fab onClick={this.handleOpen.bind(this)}
             color='secondary' aria-label='Edit'
             className={classes.editButton}><Edit/></Fab>
        <Drawer open={this.state.open} anchor='right' classes={{ paper: classes.drawerPaper }} onClose={this.handleClose.bind(this)}>
          <QueryRenderer
              query={reportEditionQuery}
              variables={{ id: reportId }}
              render={({ props }) => {
                if (props) { // Done
                  return <ReportEditionContainer me={props.me} report={props.report}
                                                  handleClose={this.handleClose.bind(this)}/>;
                }
                // Loading
                return <div> &nbsp; </div>;
              }}
          />
        </Drawer>
      </div>
    );
  }
}

ReportEdition.propTypes = {
  reportId: PropTypes.string,
  me: PropTypes.object,
  report: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ReportEdition);
