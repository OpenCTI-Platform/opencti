import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import Markdown from 'react-markdown';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../components/i18n';
import { truncate } from '../../../utils/String';

const styles = theme => ({
  paper: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
});

class ReportOverviewComponent extends Component {
  render() {
    const {
      t, fld, classes, report,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Report type')}
          </Typography>
          {t(`report_${report.report_class}`)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creation date')}
          </Typography>
          {fld(report.created)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Modification date')}
          </Typography>
          {fld(report.modified)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Description')}
          </Typography>
          <Markdown
            className="markdown"
            source={truncate(report.description, 250)}
          />
        </Paper>
      </div>
    );
  }
}

ReportOverviewComponent.propTypes = {
  report: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const ReportOverview = createFragmentContainer(ReportOverviewComponent, {
  report: graphql`
    fragment ReportOverview_report on Report {
      id
      name
      description
      created
      modified
      report_class
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(ReportOverview);
