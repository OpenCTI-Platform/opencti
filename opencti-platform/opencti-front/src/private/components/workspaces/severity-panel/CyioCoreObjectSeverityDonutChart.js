import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, map, assoc } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import {
  ResponsiveContainer, PieChart, Pie, Cell,
} from 'recharts';
import { withTheme, withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Tooltip from 'rich-markdown-editor/dist/components/Tooltip';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';

const styles = () => ({
  paper: {
    height: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
});

const CyioCoreObjectRiskBySeverityDonutQuery = graphql`
  query CyioCoreObjectSeverityDonutChartQuery(
    $type: String
    $match: [String]
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
  ) {
    risksDistribution(
      type: $type
      match: $match
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
    ) {
      label
      value
    }
  }
`;

const COLORS = {
  open: '#FFD773',
  investigating: '#FFB000',
  remediating: '#F17B00',
  deviation_requested: '#FF4100',
  deviation_approved: '#FF0000',
  Informational: '#FFEBBC',
};

class CyioCoreObjectTotalAcceptedRiskDonutChart extends Component {
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
    const {
      cx, cy, midAngle, outerRadius, fill, payload, percent, value,
    } = props;
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
    const {
      t,
      toTypes,
      field,
      startDate,
      endDate,
    } = this.props;
    const finalStartDate = startDate || monthsAgo(12);
    const finalEndDate = endDate || now();
    const riskDistributionVariables = {
      type: 'Risk',
      field: 'risk_level',
      match: ['very-high', 'high', 'moderate', 'low', 'very-low'],
      startDate: finalStartDate,
      endDate: finalEndDate,
    };
    return (
      <QueryRenderer
        query={CyioCoreObjectRiskBySeverityDonutQuery}
        variables={riskDistributionVariables}
        render={({ props }) => {
          if (
            props
            && props.risksDistribution
            && props.risksDistribution.length > 0
          ) {
            let data = props.risksDistribution;
            if (field === 'internal_id') {
              data = map(
                (n) => assoc(
                  'label',
                  `${toTypes.length > 1
                    ? `[${t(`entity_${n.entity.entity_type}`)}] ${n.entity.name
                    }`
                    : `${n.entity.name}`
                  }`,
                  n,
                ),
                props.risksDistribution,
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
                  {props.risksDistribution
                    && <Pie
                      cx='45%'
                      cy='45%'
                      data={props.risksDistribution}
                      fill="#82ca9d"
                      nameKey="name"
                      dataKey="value"
                      innerRadius='50%'
                      outerRadius='80%'
                      labelLine={true}
                      isAnimationActive={false}
                      isUpdateAnimationActive={true}
                      label={({
                        cx,
                        cy,
                        value,
                        index,
                        midAngle,
                        innerRadius,
                        outerRadius,
                      }) => {
                        const RADIAN = Math.PI / 180;
                        // eslint-disable-next-line
                        const radius =
                          25 + innerRadius + (outerRadius - innerRadius);
                        // eslint-disable-next-line
                        const x =
                          cx + radius * Math.cos(-midAngle * RADIAN);
                        // eslint-disable-next-line
                        const y =
                          cy + radius * Math.sin(-midAngle * RADIAN);
                        return (
                          <text
                            x={x}
                            y={y}
                            fill={COLORS[data[index].label]}
                            textAnchor={x > cx ? 'start' : 'end'}
                            dominantBaseline="central"
                            style={{ fontSize: '15px' }}
                          >
                            {data[index].label} ({value})
                          </text>
                        );
                      }}
                    >
                      {data.map((entry, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={COLORS[entry.label]}
                        />
                      ))}
                    </Pie>
                  }
                  <Tooltip content='Accepted Risks' />
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
    const {
      t, classes, title, variant, height,
    } = this.props;
    return (
      <div style={{ height: height || '100%', padding: '20px' }}>
        <Typography variant="h4" gutterBottom={true}>
          {title || t('Total Active Risks')}
        </Typography>
        {variant === 'inLine' ? (
          this.renderContent()
        ) : (
          <Paper classes={{ root: classes.paper }} elevation={2}>
            {this.renderContent()}
          </Paper>
        )}
      </div>
    );
  }
}

CyioCoreObjectTotalAcceptedRiskDonutChart.propTypes = {
  title: PropTypes.string,
  field: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  height: PropTypes.number,
  startDate: PropTypes.object,
  endDate: PropTypes.object,
  dateAttribute: PropTypes.string,
  variant: PropTypes.string,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(CyioCoreObjectTotalAcceptedRiskDonutChart);
