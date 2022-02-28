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
import { monthsAgo, now } from '../../../../utils/Time';
import { verticalBarsChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';

const styles = () => ({
  paper: {
    minHeight: 280,
    height: '100%',
    margin: '4px 0 0 0',
    padding: '0 0 10px 0',
    borderRadius: 6,
  },
  chip: {
    fontSize: 10,
    height: 20,
    marginLeft: 10,
  },
});

const reporstVerticalBarsTimeSeriesQuery = graphql`
  query IndicatorsVerticalBarsTimeSeriesQuery(
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
  ) {
    indicatorsTimeSeries(
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
    ) {
      date
      value
    }
  }
`;

class IndicatorsVerticalBars extends Component {
  renderContent() {
    const { t, fsd, indicatorType, startDate, endDate, theme } = this.props;
    const interval = 'day';
    const finalStartDate = startDate || monthsAgo(12);
    const finalEndDate = endDate || now();
    const indicatorsTimeSeriesVariables = {
      indicatorType: indicatorType || null,
      field: 'created_at',
      operation: 'count',
      startDate: finalStartDate,
      endDate: finalEndDate,
      interval,
    };
    return (
      <QueryRenderer
        query={reporstVerticalBarsTimeSeriesQuery}
        variables={indicatorsTimeSeriesVariables}
        render={({ props }) => {
          if (props && props.indicatorsTimeSeries) {
            const chartData = props.indicatorsTimeSeries.map((entry) => ({
              x: new Date(entry.date),
              y: entry.value,
            }));
            return (
              <Chart
                options={verticalBarsChartOptions(
                  theme,
                  fsd,
                  simpleNumberFormat,
                  false,
                  true,
                )}
                series={[
                  {
                    name: t('Number of indicators'),
                    data: chartData,
                  },
                ]}
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
          {title || t('Indicators history')}
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

IndicatorsVerticalBars.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  md: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(IndicatorsVerticalBars);
