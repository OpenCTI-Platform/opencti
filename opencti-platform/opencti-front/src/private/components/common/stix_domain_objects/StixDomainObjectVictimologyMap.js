import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, prop, uniqBy } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import LocationMiniMapTargets from '../location/LocationMiniMapTargets';
import { QueryRenderer } from '../../../../relay/environment';
import { stixDomainObjectVictimologyRegionsStixCoreRelationshipsQuery } from './StixDomainObjectVictimologyRegions';

const styles = () => ({
  paper: {
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
});

class StixDomainObjectVictimologyMap extends Component {
  render() {
    const {
      t, title, stixDomainObjectId, startDate, endDate,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {title || t('Victimology map')}
        </Typography>
        <QueryRenderer
          query={stixDomainObjectVictimologyRegionsStixCoreRelationshipsQuery}
          variables={{
            first: 500,
            fromId: stixDomainObjectId,
            toTypes: ['Region', 'Country', 'City'],
            relationship_type: 'targets',
            startDate,
            endDate,
          }}
          render={({ props }) => {
            if (props && props.data) {
              const { data } = props;
              // Extract all regions
              const regions = data.stixCoreRelationships.edges
                .map((e) => e.node)
                .filter((n) => n.to.entity_type === 'Region')
                .map((e) => e.to);
              const regionCountries = regions
                .map((region) => region.countries.edges)
                .flat()
                .map((e) => e.node);
              const directCountries = data.stixCoreRelationships.edges
                .map((e) => e.node)
                .filter((n) => n.to.entity_type === 'Country')
                .map((e) => e.to);
              const countries = uniqBy(prop('name'), [
                ...directCountries,
                ...regionCountries,
              ]);
              const cities = data.stixCoreRelationships.edges
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
