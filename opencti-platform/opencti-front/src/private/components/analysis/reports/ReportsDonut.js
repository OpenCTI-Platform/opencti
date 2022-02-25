import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { assoc, compose, map } from 'ramda';
import { graphql } from 'react-relay';
import { ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';

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

const reportsDonutDistributionQuery = graphql`
  query ReportsDonutDistributionQuery(
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

class ReportsDonut extends Component {
  constructor(props) {
    super(props);
    this.renderLabel = this.renderLabel.bind(this);
    this.renderSimpleLabel = this.renderSimpleLabel.bind(this);
  }

  // eslint-disable-next-line class-methods-use-this
  renderSimpleLabel(props) {
    return props.value;
  }

  renderLabel(props) {
    const { theme } = this.props;
    const RADIAN = Math.PI / 180;
    const { cx, cy, midAngle, outerRadius, fill, payload, percent, value } = props;
    const sin = Math.sin(-RADIAN * midAngle);
    const cos = Math.cos(-RADIAN * midAngle);
    const sx = cx + (outerRadius + 10) * cos;
    const sy = cy + (outerRadius + 10) * sin;
    const mx = cx + (outerRadius + 30) * cos;
    const my = cy + (outerRadius + 30) * sin;
    const ex = mx + (cos >= 0 ? 1 : -1) * 22;
    const ey = my;
    const textAnchor = cos >= 0 ? 'start' : 'end';

    return (
      <g>
        <path
          d={`M${sx},${sy}L${mx},${my}L${ex},${ey}`}
          stroke={fill}
          fill="none"
        />
        <circle cx={ex} cy={ey} r={2} fill={fill} stroke="none" />
        <text
          x={ex + (cos >= 0 ? 1 : -1) * 12}
          y={ey}
          textAnchor={textAnchor}
          fill={theme.palette.text.primary}
          style={{ fontSize: 12 }}
        >
          {' '}
          {payload.label} ({value})
        </text>
        <text
          x={ex + (cos >= 0 ? 1 : -1) * 12}
          y={ey}
          dy={18}
          textAnchor={textAnchor}
          fill="#999999"
          style={{ fontSize: 12 }}
        >
          {` ${(percent * 100).toFixed(2)}%`}
        </text>
      </g>
    );
  }

  renderContent() {
    const { t, field, startDate, endDate, variant, theme } = this.props;
    const reportsDistributionVariables = {
      field: field || 'report_types',
      operation: 'count',
      limit: 8,
      startDate,
      endDate,
    };
    return (
      <QueryRenderer
        query={reportsDonutDistributionQuery}
        variables={reportsDistributionVariables}
        render={({ props }) => {
          if (
            props
            && props.reportsDistribution
            && props.reportsDistribution.length > 0
          ) {
            let data = props.reportsDistribution;
            if (field && field.includes('internal_id')) {
              data = map(
                (n) => assoc('label', n.entity.name, n),
                props.reportsDistribution,
              );
            }
            return (
              <ResponsiveContainer height="100%" width="100%">
                <PieChart
                  margin={{
                    top: 0,
                    right: 0,
                    bottom: 0,
                    left: 0,
                  }}
                >
                  <Pie
                    data={data}
                    dataKey="value"
                    nameKey="label"
                    cx="50%"
                    cy="50%"
                    innerRadius="63%"
                    outerRadius="80%"
                    fill="#82ca9d"
                    label={
                      variant === 'inEntity'
                        ? this.renderLabel
                        : this.renderSimpleLabel
                    }
                    labelLine={true}
                    paddingAngle={5}
                  >
                    {data.map((entry, index) => (
                      <Cell
                        key={index}
                        fill={itemColor(entry.label)}
                        stroke={theme.palette.background.paper}
                      />
                    ))}
                  </Pie>
                  {variant === 'inLine' && <Legend margin={{ bottom: 20 }} />}
                </PieChart>
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

ReportsDonut.propTypes = {
  title: PropTypes.string,
  field: PropTypes.string,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withTheme, withStyles(styles))(ReportsDonut);
