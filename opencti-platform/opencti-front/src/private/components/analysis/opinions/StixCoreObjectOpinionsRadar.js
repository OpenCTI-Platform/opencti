import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import {
  ResponsiveContainer,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
} from 'recharts';
import { withTheme, withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';

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

const stixCoreObjectOpinionsRadarDistributionQuery = graphql`
  query StixCoreObjectOpinionsRadarDistributionQuery(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $limit: Int
  ) {
    opinionsDistribution(
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

class StixCoreObjectOpinionsRadar extends Component {
  render() {
    const {
      t, stixCoreObjectId, field, theme,
    } = this.props;
    const opinionsDistributionVariables = {
      objectId: stixCoreObjectId,
      field: field || 'opinion_types',
      operation: 'count',
      limit: 8,
    };
    return (
      <QueryRenderer
        query={stixCoreObjectOpinionsRadarDistributionQuery}
        variables={opinionsDistributionVariables}
        render={({ props }) => {
          if (props && props.opinionsDistribution) {
            let data = props.opinionsDistribution;
            if (field && field.includes('internal_id')) {
              data = R.map(
                (n) => R.assoc('label', n.entity.name, n),
                props.opinionsDistribution,
              );
            }
            data = R.indexBy(R.prop('label'), data);
            const radarData = [
              {
                label: 'strongly-disagree',
                value: data['strongly-disagree'] || 0,
              },
              { label: 'disagree', value: data.disagree || 0 },
              { label: 'neutral', value: data.neutral || 20 },
              { label: 'agree', value: data.agree || 10 },
              { label: 'strongly-agree', value: data['strongly-agree'] || 0 },
            ];
            return (
              <ResponsiveContainer width="100%" height="100%">
                <RadarChart
                  cx="50%"
                  cy="50%"
                  outerRadius="80%"
                  data={radarData}
                >
                  <PolarGrid stroke={theme.palette.navBottom.background} />
                  <PolarAngleAxis
                    dataKey="label"
                    tick={{ fill: theme.palette.text.primary }}
                  />
                  <PolarRadiusAxis />
                  <Radar
                    dataKey="value"
                    stroke={theme.palette.background.default}
                    fill={theme.palette.primary.main}
                    fillOpacity={0.2}
                  />
                </RadarChart>
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
}

StixCoreObjectOpinionsRadar.propTypes = {
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
)(StixCoreObjectOpinionsRadar);
