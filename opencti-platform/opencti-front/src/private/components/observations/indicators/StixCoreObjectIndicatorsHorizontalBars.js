import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
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
import { withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import Theme from '../../../../components/ThemeDark';
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

const stixCoreObjectIndicatorsHorizontalBarsDistributionQuery = graphql`
  query StixCoreObjectIndicatorsHorizontalBarsDistributionQuery(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $limit: Int
  ) {
    indicatorsDistribution(
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
      }
    }
  }
`;

const tickFormatter = (title) => truncate(title, 10);

class StixCoreObjectIndicatorsHorizontalBars extends Component {
  renderContent() {
    const { t, stixCoreObjectId, field } = this.props;
    const indicatorsDistributionVariables = {
      objectId: stixCoreObjectId,
      field: field || 'indicator_types',
      operation: 'count',
      limit: 8,
    };
    return (
      <QueryRenderer
        query={stixCoreObjectIndicatorsHorizontalBarsDistributionQuery}
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
                    left: 0,
                  }}
                >
                  <XAxis
                    type="number"
                    dataKey="value"
                    stroke="#ffffff"
                    allowDecimals={false}
                  />
                  <YAxis
                    stroke="#ffffff"
                    dataKey={field.includes('.') ? 'entity.name' : 'label'}
                    type="category"
                    angle={-30}
                    textAnchor="end"
                    tickFormatter={tickFormatter}
                  />
                  <CartesianGrid strokeDasharray="2 2" stroke="#0f181f" />
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
                    fill={Theme.palette.primary.main}
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
    const {
      t, classes, title, variant, height,
    } = this.props;
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

StixCoreObjectIndicatorsHorizontalBars.propTypes = {
  stixCoreObjectId: PropTypes.string,
  title: PropTypes.string,
  field: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectIndicatorsHorizontalBars);
