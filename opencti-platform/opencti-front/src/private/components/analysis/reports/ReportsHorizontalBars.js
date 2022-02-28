import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Chart from 'react-apexcharts';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { horizontalBarsChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';

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

const reportsHorizontalBarsDistributionQuery = graphql`
  query ReportsHorizontalBarsDistributionQuery(
    $field: String!
    $operation: StatsOperation!
    $limit: Int
    $startDate: DateTime
    $endDate: DateTime
  ) {
    reportsDistribution(
      field: $field
      operation: $operation
      limit: $limit
      startDate: $startDate
      endDate: $endDate
    ) {
      label
      value
      entity {
        ... on Identity {
          name
        }
      }
    }
  }
`;

class ReportsHorizontalBars extends Component {
  renderContent() {
    const { t, field, startDate, endDate, theme } = this.props;
    const reportsDistributionVariables = {
      field: field || 'report_types',
      operation: 'count',
      limit: 8,
      startDate,
      endDate,
    };
    return (
      <QueryRenderer
        query={reportsHorizontalBarsDistributionQuery}
        variables={reportsDistributionVariables}
        render={({ props }) => {
          if (
            props
            && props.reportsDistribution
            && props.reportsDistribution.length > 0
          ) {
            const data = props.reportsDistribution.map((n) => ({
              x: n.entity.name,
              y: n.value,
            }));
            const chartData = [{ name: t('Number of reports'), data }];
            return (
              <Chart
                options={horizontalBarsChartOptions(
                  theme,
                  true,
                  simpleNumberFormat,
                  null,
                  true,
                )}
                series={chartData}
                type="bar"
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

ReportsHorizontalBars.propTypes = {
  title: PropTypes.string,
  field: PropTypes.string,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(ReportsHorizontalBars);
