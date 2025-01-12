import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Chart from '../charts/Chart';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { horizontalBarsChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { NO_DATA_WIDGET_MESSAGE } from '../../../../components/dashboard/WidgetNoData';

const styles = () => ({
  paper: {
    height: 150,
    minHeight: 150,
    maxHeight: 150,
    margin: '10px 0 20px 0',
    padding: '0 10px 10px 0',
    borderRadius: 4,
  },
});

const stixCoreObjectContainersHorizontalBarDistributionQuery = graphql`
  query StixCoreObjectContainersHorizontalBarDistributionQuery(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $limit: Int
  ) {
    containersDistribution(
      objectId: $objectId
      field: $field
      operation: $operation
      limit: $limit
    ) {
      label
      value
      entity {
        ... on StixObject {
          representative {
            main
          }
        }
      }
    }
  }
`;

class StixCoreObjectContainersHorizontalBar extends Component {
  renderContent() {
    const { t, stixCoreObjectId, field, theme } = this.props;
    const containersDistributionVariables = {
      objectId: stixCoreObjectId,
      field: field || 'container_types',
      operation: 'count',
      limit: 20,
    };
    return (
      <QueryRenderer
        query={stixCoreObjectContainersHorizontalBarDistributionQuery}
        variables={containersDistributionVariables}
        render={({ props }) => {
          if (
            props
            && props.containersDistribution
            && props.containersDistribution.length > 0
          ) {
            const chartData = props.containersDistribution.map((n) => ({
              name: getMainRepresentative(n.entity) || n.label,
              data: [n.value],
            }));
            return (
              <Chart
                options={horizontalBarsChartOptions(
                  theme,
                  true,
                  simpleNumberFormat,
                  null,
                  false,
                  undefined,
                  null,
                  true,
                  false,
                  ['Number of containers'],
                  true,
                  '100%',
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
                  {t(NO_DATA_WIDGET_MESSAGE)}
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
          {title || t('Containers distribution')}
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

StixCoreObjectContainersHorizontalBar.propTypes = {
  stixCoreObjectId: PropTypes.string,
  title: PropTypes.string,
  field: PropTypes.string,
  theme: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixCoreObjectContainersHorizontalBar);
