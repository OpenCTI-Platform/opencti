import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Chip from '@material-ui/core/Chip';
import inject18n from '../../../components/i18n';
import ExpandableMarkdown from '../../../components/ExpandableMarkdown';
import ItemAuthor from '../../../components/ItemAuthor';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: 'rgba(0, 150, 136, 0.3)',
    color: '#ffffff',
    textTransform: 'uppercase',
    borderRadius: '0',
  },
});

class ReportOverviewComponent extends Component {
  render() {
    const {
      t, fld, classes, report,
    } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Report type')}
          </Typography>
          <Chip
            classes={{ root: classes.chip }}
            label={report.report_class}
          />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Publication date')}
          </Typography>
          {fld(report.published)}
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
            {t('Author')}
          </Typography>
          <ItemAuthor
            createdByRef={pathOr(null, ['createdByRef', 'node'], report)}
          />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Description')}
          </Typography>
          <ExpandableMarkdown
            className="markdown"
            source={report.description}
            limit={250}
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
      published
      modified
      report_class
      createdByRef {
        node {
          id
          name
          entity_type
        }
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(ReportOverview);
