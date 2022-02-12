import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, prop, uniqBy } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Typography from '@mui/material/Typography';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../components/i18n';
import LocationMiniMapTargets from '../location/LocationMiniMapTargets';
import { QueryRenderer } from '../../../../relay/environment';

const styles = () => ({
  paper: {
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
});

const stixDomainObjectVictimologyMapQuery = graphql`
  query StixDomainObjectVictimologyMapQuery(
    $fromId: String
    $toTypes: [String]
    $relationship_type: [String]
    $first: Int
    $startDate: DateTime
    $endDate: DateTime
  ) {
    stixCoreRelationships(
      fromId: $fromId
      toTypes: $toTypes
      relationship_type: $relationship_type
      first: $first
      startDate: $startDate
      endDate: $endDate
    ) {
      edges {
        node {
          id
          description
          start_time
          stop_time
          to {
            ... on BasicObject {
              id
              entity_type
            }
            ... on City {
              name
              latitude
              longitude
              country {
                id
                name
                x_opencti_aliases
                region {
                  id
                  name
                }
              }
            }
            ... on Country {
              id
              name
              x_opencti_aliases
              region {
                id
                name
              }
            }
            ... on Region {
              name
              x_opencti_aliases
              countries {
                edges {
                  node {
                    name
                    x_opencti_aliases
                  }
                }
              }
            }
          }
          objectMarking {
            edges {
              node {
                id
                definition
                x_opencti_color
              }
            }
          }
        }
      }
    }
  }
`;

class StixDomainObjectVictimologyMap extends Component {
  render() {
    const {
      t, title, stixDomainObjectId, startDate, endDate,
    } = this.props;
    return (
      <div style={{ height: '100%', paddingBottom: 10 }}>
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{ marginBottom: 10 }}
        >
          {title || t('Victimology map')}
        </Typography>
        <QueryRenderer
          query={stixDomainObjectVictimologyMapQuery}
          variables={{
            first: 500,
            fromId: stixDomainObjectId,
            toTypes: ['Region', 'Country', 'City'],
            relationship_type: 'targets',
            startDate,
            endDate,
          }}
          render={({ props }) => {
            if (props && props.stixCoreRelationships) {
              // Extract all regions
              const regions = props.stixCoreRelationships.edges
                .map((e) => e.node)
                .filter((n) => n.to.entity_type === 'Region')
                .map((e) => e.to);
              const regionCountries = regions
                .map((region) => region.countries.edges)
                .flat()
                .map((e) => e.node);
              const directCountries = props.stixCoreRelationships.edges
                .map((e) => e.node)
                .filter((n) => n.to.entity_type === 'Country')
                .map((e) => e.to);
              const countries = uniqBy(prop('name'), [
                ...directCountries,
                ...regionCountries,
              ]);
              const cities = props.stixCoreRelationships.edges
                .map((e) => e.node)
                .filter((n) => n.to.entity_type === 'City')
                .map((e) => e.to);
              return (
                <LocationMiniMapTargets
                  center={[48.8566969, 2.3514616]}
                  zoom={2.5}
                  countries={countries}
                  cities={cities}
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

StixDomainObjectVictimologyMap.propTypes = {
  stixDomainObjectId: PropTypes.string,
  classes: PropTypes.object,
  title: PropTypes.string,
  t: PropTypes.func,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectVictimologyMap);
