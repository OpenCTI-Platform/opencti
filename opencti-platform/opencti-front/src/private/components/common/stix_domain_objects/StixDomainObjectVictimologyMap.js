import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Typography from '@mui/material/Typography';
import { graphql } from 'react-relay';
import Paper from '@mui/material/Paper';
import inject18n from '../../../../components/i18n';
import LocationMiniMapTargets from '../location/LocationMiniMapTargets';
import { QueryRenderer } from '../../../../relay/environment';
import { computeLevel } from '../../../../utils/Number';

const styles = () => ({
  paper: {
    height: '100%',
    margin: '4px 0 0 0',
    borderRadius: 6,
  },
  paperExplore: {
    height: '100%',
    margin: 0,
    padding: '0 0 10px 0',
    borderRadius: 6,
  },
  chip: {
    fontSize: 10,
    height: 20,
    marginLeft: 10,
  },
  updateButton: {
    float: 'right',
    margin: '7px 10px 0 0',
  },
});

const stixDomainObjectVictimologyMapQuery = graphql`
  query StixDomainObjectVictimologyMapQuery(
    $fromId: StixRef
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
      fromId: $fromId
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

class StixDomainObjectVictimologyMap extends Component {
  renderContent() {
    const { stixDomainObjectId, startDate, endDate, timeField } = this.props;
    return (
      <QueryRenderer
        query={stixDomainObjectVictimologyMapQuery}
        variables={{
          fromId: stixDomainObjectId,
          field: 'internal_id',
          operation: 'count',
          relationship_type: 'targets',
          toTypes: ['Country'],
          startDate,
          endDate,
          dateAttribute:
            timeField === 'functional' ? 'start_time' : 'created_at',
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
              props.stixCoreRelationshipsDistribution,
            );
            return (
              <LocationMiniMapTargets
                center={[48.8566969, 2.3514616]}
                countries={countries}
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
    );
  }

  render() {
    const { t, title, variant, classes } = this.props;
    return (
      <div
        style={{ height: '100%', paddingBottom: variant !== 'inLine' ? 0 : 10 }}
      >
        <Typography
          variant={variant === 'inEntity' ? 'h3' : 'h4'}
          gutterBottom={true}
          style={{
            margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px',
          }}
        >
          {title || t('Victimology map')}
        </Typography>
        {variant === 'inLine' || variant === 'inEntity' ? (
          this.renderContent()
        ) : (
          <Paper classes={{ root: classes.paper }} variant="outlined">
            {this.renderContent()}
          </Paper>
        )}
      </div>
    );
  }
}

StixDomainObjectVictimologyMap.propTypes = {
  stixDomainObjectId: PropTypes.string,
  classes: PropTypes.object,
  title: PropTypes.string,
  t: PropTypes.func,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectVictimologyMap);
