import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../components/i18n';
import ReportHeader from './ReportHeader';
import ReportOverview from './ReportOverview';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class ReportComponent extends Component {
  render() {
    const { classes, reportId, report } = this.props;
    return (
      <div className={classes.container}>
        <ReportHeader report={report}/>
        <Grid container={true} spacing={32} classes={{ container: classes.gridContainer }}>
          <Grid item={true} xs={6}>
            <ReportOverview report={report}/>
          </Grid>
          <Grid item={true} xs={6}>
            &nbsp;
          </Grid>
        </Grid>
        <Grid container={true} spacing={32} classes={{ container: classes.gridContainer }} style={{ marginTop: 20 }}>
          <Grid item={true} xs={4}>
            &nbsp;
          </Grid>
        </Grid>
      </div>
    );
  }
}

ReportComponent.propTypes = {
  reportId: PropTypes.string.isRequired,
  report: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Report = createFragmentContainer(ReportComponent, {
  report: graphql`
      fragment Report_report on Report {
          ...ReportHeader_report
          ...ReportOverview_report
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(Report);
