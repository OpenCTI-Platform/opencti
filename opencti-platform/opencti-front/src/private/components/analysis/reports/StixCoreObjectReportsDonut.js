import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql } from 'react-relay';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Chart from 'react-apexcharts';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { donutChartOptions } from '../../../../utils/Charts';

const styles = () => ({
  paper: {
    height: 300,
    minHeight: 300,
    maxHeight: 300,
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
});

const stixCoreObjectReportsDonutDistributionQuery = graphql`
  query StixCoreObjectReportsDonutDistributionQuery(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $limit: Int
  ) {
    reportsDistribution(
      objectId: $objectId
      field: $field
      operation: $operation
      limit: $limit
    ) {
      label
      value
      entity {
        ... on Identity {
          name
        }
        ... on Malware {
          name
        }
      }
    }
  }
`;

class StixCoreObjectReportsDonut extends Component {
  renderContent() {
    const { t, stixCoreObjectId, field, theme } = this.props;
    const reportsDistributionVariables = {
      objectId: stixCoreObjectId,
      field: field || 'report_types',
      operation: 'count',
      limit: 8,
    };
    return (
      <QueryRenderer
        query={stixCoreObjectReportsDonutDistributionQuery}
        variables={reportsDistributionVariables}
        render={({ props }) => {
          if (
            props
            && props.reportsDistribution
            && props.reportsDistribution.length > 0
          ) {
            let data = props.reportsDistribution;
            if (field && field.includes('internal_id')) {
              data = R.map(
                (n) => R.assoc('label', n.entity.name, n),
                props.reportsDistribution,
              );
            }
            const chartData = data.map((n) => n.value);
            const labels = data.map((n) => n.label);
            return (
              <Chart
                options={donutChartOptions(theme, labels)}
                series={chartData}
                type="donut"
                width="100%"
                height="100%"
              />
            );
          }
          if (props) {
            return (
              <div style={{ display: 'table', height: '100%', width: '100%' }}>
                <span
                  style={{
                    display: 'table-cell',
                    verticalAlign: 'middle',
                    textAlign: 'center',
                  }}
                >
                  {t('No entities of this type has been found.')}
                </span>
              </div>
            );
          }
          return (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                <CircularProgress size={40} thickness={2} />
              </span>
            </div>
          );
        }}
      />
    );
  }

  render() {
    const { t, classes, title, variant, height } = this.props;
    return (
      <div style={{ height: height || '100%' }}>
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{
            margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px',
          }}
        >
          {title || t('Reports distribution')}
        </Typography>
        {variant !== 'inLine' ? (
          <Paper classes={{ root: classes.paper }} variant="outlined">
            {this.renderContent()}
          </Paper>
        ) : (
          this.renderContent()
        )}
      </div>
    );
  }
}

StixCoreObjectReportsDonut.propTypes = {
  stixCoreObjectId: PropTypes.string,
  title: PropTypes.string,
  field: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixCoreObjectReportsDonut);
