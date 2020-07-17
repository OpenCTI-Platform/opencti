import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../components/i18n';
import ItemStatus from '../../../components/ItemStatus';
import ItemConfidence from '../../../components/ItemConfidence';
import StixDomainObjectLabels from '../common/stix_domain_objects/StixDomainObjectLabels';
import ItemCreator from '../../../components/ItemCreator';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class ReportDetailsComponent extends Component {
  render() {
    const { t, classes, report } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <StixDomainObjectLabels labels={report.labels} id={report.id} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creator')}
          </Typography>
          <ItemCreator creator={report.creator} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Processing status')}
          </Typography>
          <ItemStatus
            label={t(
              `${
                report.object_status
                  ? `report_status_${report.object_status}`
                  : 'report_status_0'
              }`,
            )}
            status={report.object_status}
          />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Confidence level')}
          </Typography>
          <ItemConfidence level={report.confidence} />
        </Paper>
      </div>
    );
  }
}

ReportDetailsComponent.propTypes = {
  report: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const ReportDetails = createFragmentContainer(ReportDetailsComponent, {
  report: graphql`
    fragment ReportDetails_report on Report {
      id
      object_status
      confidence
      creator {
        id
        name
      }
      labels {
        edges {
          node {
            id
            value
            color
          }
          relation {
            id
          }
        }
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(ReportDetails);
