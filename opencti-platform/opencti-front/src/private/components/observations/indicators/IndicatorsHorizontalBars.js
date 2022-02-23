import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import {
  BarChart,
  XAxis,
  YAxis,
  Cell,
  CartesianGrid,
  Bar,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import { truncate } from '../../../../utils/String';

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

const indicatorsHorizontalBarsDistributionQuery = graphql`
  query IndicatorsHorizontalBarsDistributionQuery(
    $field: String!
    $operation: StatsOperation!
    $limit: Int
    $startDate: DateTime
    $endDate: DateTime
  ) {
    indicatorsDistribution(
      field: $field
      operation: $operation
      limit: $limit
      startDate: $startDate
      endDate: $endDate
    ) {
      label
      value
      entity {
        ... on Indicator {
          name
        }
      }
    }
  }
`;

const tickFormatter = (title) => truncate(title, 10);

class IndicatorsHorizontalBars extends Component {
  renderContent() {
    const { t, field, startDate, endDate, theme } = this.props;
    const indicatorsDistributionVariables = {
      field: field || 'pattern_type',
      operation: 'count',
      limit: 8,
      startDate,
      endDate,
    };
    return (
      <QueryRenderer
        query={indicatorsHorizontalBarsDistributionQuery}
        variables={indicatorsDistributionVariables}
        render={({ props }) => {
          if (
            props
            && props.indicatorsDistribution
            && props.indicatorsDistribution.length > 0
          ) {
            return (
              <ResponsiveContainer height="100%" width="100%">
                <BarChart
                  layout="vertical"
                  data={props.indicatorsDistribution}
                  margin={{
                    top: 20,
                    right: 20,
                    bottom: 0,
                    left: 20,
                  }}
                >
                  <XAxis
                    type="number"
                    dataKey="value"
                    stroke={theme.palette.text.primary}
                    allowDecimals={false}
                  />
                  <YAxis
                    stroke={theme.palette.text.primary}
                    dataKey={field.includes('.') ? 'entity.name' : 'label'}
                    type="category"
                    angle={-30}
                    textAnchor="end"
                    tickFormatter={tickFormatter}
                  />
                  <CartesianGrid
                    strokeDasharray="2 2"
                    stroke={theme.palette.action.grid}
                  />
                  <Tooltip
                    cursor={{
                      fill: 'rgba(0, 0, 0, 0.2)',
                      stroke: 'rgba(0, 0, 0, 0.2)',
                      strokeWidth: 2,
                    }}
                    contentStyle={{
                      backgroundColor: 'rgba(255, 255, 255, 0.1)',
                      fontSize: 12,
                      borderRadius: 10,
                    }}
                  />
                  <Bar
                    fill={theme.palette.primary.main}
                    dataKey="value"
                    barSize={15}
                  >
                    {props.indicatorsDistribution.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={itemColor(entry.label)}
                      />
                    ))}
                  </Bar>
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
    const { t, classes, title, variant, height } = this.props;
    return (
      <div style={{ height: height || '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {title || t('Indicators distribution')}
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

IndicatorsHorizontalBars.propTypes = {
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
)(IndicatorsHorizontalBars);
