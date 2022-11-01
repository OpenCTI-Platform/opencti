import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import {
  BarChart,
  ResponsiveContainer,
  CartesianGrid,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts';
import { withStyles, withTheme } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';

const styles = () => ({
  paper: {
    minHeight: 280,
    height: '100%',
    margin: '4px 0 0 0',
    padding: '1rem',
    borderRadius: 6,
  },
  chip: {
    fontSize: 10,
    height: 20,
    marginLeft: 10,
  },
});

const cyioCoreObjectRiskOccurrencesVerticalBarsQuery = graphql`
  query CyioCoreObjectRiskOccurrencesVerticalBarsQuery(
    $type: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
  ) {
    risksDistribution(
      type: $type
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
    ) {
      label
      value
      entity {
        ... on Risk {
          id
          created
          name
          first_seen
          last_seen
          risk_level
          occurrences
          deadline
        }
      }
    }
  }
`;

class CyioCoreObjectRiskOccurrencesVerticalBars extends Component {
  renderContent() {
    const {
      t,
      md,
      startDate,
      endDate,
      theme,
    } = this.props;
    const finalStartDate = startDate || monthsAgo(12);
    const finalEndDate = endDate || now();
    const riskDistributionVariables = {
      type: 'Risk',
      field: 'occurrences',
      operation: 'count',
      startDate: finalStartDate,
      endDate: finalEndDate,
    };

    return (
      <QueryRenderer
        query={cyioCoreObjectRiskOccurrencesVerticalBarsQuery}
        variables={riskDistributionVariables}
        render={({ props }) => {
          if (props && props.risksDistribution) {
            return (
              <ResponsiveContainer height="100%" width="100%">
                <BarChart
                  layout='vertical'
                  data={props.risksDistribution}
                  margin={{
                    top: 20,
                    right: 20,
                    bottom: 0,
                    left: 0,
                  }}
                  barGap={0}
                >
                  <CartesianGrid
                    strokeDasharray="2 2"
                    stroke='rgba(241, 241, 242, 0.35)'
                    // stroke={theme.palette.action.grid}
                    vertical={false}
                  />
                  <XAxis
                    dataKey='value'
                    stroke={theme.palette.text.primary}
                  // interval={interval}
                  // angle={-45}
                  // textAnchor="end"
                  // tickFormatter={md}
                  />
                  <YAxis type='category' dataKey='label' stroke={theme.palette.text.primary} />
                  <Tooltip
                    cursor={{
                      fill: 'rgba(0, 0, 0, 0.2)',
                      stroke: 'rgba(0, 0, 0, 0.2)',
                      strokeWidth: 2,
                    }}
                    contentStyle={{
                      backgroundColor: '#1F2842',
                      fontSize: 12,
                      border: '1px solid #06102D',
                      borderRadius: 10,
                    }}
                    labelFormatter={md}
                  />
                  <Bar
                    // fill={theme.palette.primary.main}
                    fill="#075AD3"
                    dataKey="value"
                    barSize={20}
                  />
                </BarChart>
              </ResponsiveContainer>
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
    const {
      t, classes, title, variant, height,
    } = this.props;
    return (
      <div style={{ height: height || '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {title || t('Top N Risks by Severity')}
        </Typography>
        {variant !== 'inLine' ? (
          <Paper classes={{ root: classes.paper }} elevation={2}>
            {this.renderContent()}
          </Paper>
        ) : (
          this.renderContent()
        )}
      </div>
    );
  }
}

CyioCoreObjectRiskOccurrencesVerticalBars.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  md: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(CyioCoreObjectRiskOccurrencesVerticalBars);
