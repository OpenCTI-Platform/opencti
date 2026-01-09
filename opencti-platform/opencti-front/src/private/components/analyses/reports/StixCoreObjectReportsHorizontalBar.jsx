import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withTheme from '@mui/styles/withTheme';
import CircularProgress from '@mui/material/CircularProgress';
import Card from '@common/card/Card';
import Chart from '../../common/charts/Chart';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { horizontalBarsChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { NO_DATA_WIDGET_MESSAGE } from '../../../../components/dashboard/WidgetNoData';

const stixCoreObjectReportsHorizontalBarDistributionQuery = graphql`
  query StixCoreObjectReportsHorizontalBarDistributionQuery(
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
        ... on StixObject {
          representative {
            main
          }
        }
      }
    }
  }
`;

class StixCoreObjectReportsHorizontalBar extends Component {
  renderContent() {
    const { t, stixCoreObjectId, field, theme } = this.props;
    const reportsDistributionVariables = {
      objectId: stixCoreObjectId,
      field: field || 'report_types',
      operation: 'count',
      limit: 20,
    };
    return (
      <QueryRenderer
        query={stixCoreObjectReportsHorizontalBarDistributionQuery}
        variables={reportsDistributionVariables}
        render={({ props }) => {
          if (
            props
            && props.reportsDistribution
            && props.reportsDistribution.length > 0
          ) {
            const chartData = props.reportsDistribution.map((n) => ({
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
                  ['Number of reports'],
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
    const { t, title, height } = this.props;
    return (
      <div style={{ height: height || '100%', marginBottom: 24 }}>
        <Card
          padding="small"
          title={title || t('Reports distribution')}
        >
          {this.renderContent()}
        </Card>
      </div>
    );
  }
}

StixCoreObjectReportsHorizontalBar.propTypes = {
  stixCoreObjectId: PropTypes.string,
  title: PropTypes.string,
  field: PropTypes.string,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
)(StixCoreObjectReportsHorizontalBar);
