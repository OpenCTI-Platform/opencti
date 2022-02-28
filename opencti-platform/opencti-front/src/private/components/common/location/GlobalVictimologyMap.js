import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Typography from '@mui/material/Typography';
import { graphql } from 'react-relay';
import inject18n from '../../../../components/i18n';
import LocationMiniMapTargets from './LocationMiniMapTargets';
import { QueryRenderer } from '../../../../relay/environment';
import { computeLevel } from '../../../../utils/Number';

export const globalVictimologyMapStixCoreRelationshipsDistributionQuery = graphql`
  query GlobalVictimologyMapStixCoreRelationshipsDistributionQuery(
    $field: String!
    $operation: StatsOperation!
    $relationship_type: String
    $toTypes: [String]
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $limit: Int
  ) {
    stixCoreRelationshipsDistribution(
      field: $field
      operation: $operation
      relationship_type: $relationship_type
      toTypes: $toTypes
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      limit: $limit
    ) {
      label
      value
      entity {
        ... on BasicObject {
          entity_type
        }
        ... on BasicRelationship {
          entity_type
        }
        ... on Country {
          name
          x_opencti_aliases
          latitude
          longitude
        }
      }
    }
  }
`;

const styles = () => ({
  paper: {
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
});

class GlobalVictimologyMap extends Component {
  render() {
    const { t, title, startDate, endDate, dateAttribute } = this.props;
    return (
      <div style={{ height: '100%', paddingBottom: 10 }}>
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{ margin: '-10px 0 10px -7px' }}
        >
          {title || t('Victimology map')}
        </Typography>
        <QueryRenderer
          query={globalVictimologyMapStixCoreRelationshipsDistributionQuery}
          variables={{
            field: 'internal_id',
            operation: 'count',
            relationship_type: 'targets',
            toTypes: ['Country', 'City'],
            startDate,
            endDate,
            dateAttribute,
            limit: 20,
          }}
          render={({ props }) => {
            if (props && props.stixCoreRelationshipsDistribution) {
              const values = R.pluck(
                'value',
                props.stixCoreRelationshipsDistribution,
              );
              const countries = R.map(
                (x) => R.assoc(
                  'level',
                  computeLevel(x.value, R.last(values), R.head(values) + 1),
                  x.entity,
                ),
                R.filter(
                  (n) => n.entity.entity_type === 'Country',
                  props.stixCoreRelationshipsDistribution,
                ),
              );
              const cities = R.map(
                (x) => x.entity,
                R.filter(
                  (n) => n.entity.entity_type === 'City',
                  props.stixCoreRelationshipsDistribution,
                ),
              );
              return (
                <LocationMiniMapTargets
                  center={[48.8566969, 2.3514616]}
                  countries={countries}
                  cities={cities}
                  zoom={2}
                />
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
      </div>
    );
  }
}

GlobalVictimologyMap.propTypes = {
  classes: PropTypes.object,
  title: PropTypes.string,
  t: PropTypes.func,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  dateAttribute: PropTypes.string,
};

export default R.compose(inject18n, withStyles(styles))(GlobalVictimologyMap);
