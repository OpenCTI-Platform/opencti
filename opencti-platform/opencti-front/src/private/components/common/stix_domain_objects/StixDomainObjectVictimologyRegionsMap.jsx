import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, prop, uniqBy } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import inject18n from '../../../../components/i18n';
import LocationMiniMapTargets from '../location/LocationMiniMapTargets';

const styles = () => ({
  paper: {
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
    height: 'calc(100vh - 280px)',
  },
});

class StixDomainObjectVictimologyRegionsMap extends Component {
  constructor(props) {
    super(props);
    this.state = { expandedLines: {} };
  }

  render() {
    const { data, classes } = this.props;
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
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <LocationMiniMapTargets
          center={[48.8566969, 2.3514616]}
          zoom={2.5}
          countries={countries}
          cities={cities}
        />
      </Paper>
    );
  }
}

StixDomainObjectVictimologyRegionsMap.propTypes = {
  stixDomainObjectId: PropTypes.string,
  data: PropTypes.object,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectVictimologyRegionsMap);
