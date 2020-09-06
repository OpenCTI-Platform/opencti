import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  map,
  propOr,
  pluck,
  includes,
  filter,
  head,
  last,
  pipe,
} from 'ramda';
import { withStyles } from '@material-ui/core';
import Typography from '@material-ui/core/Typography';
import { Map, TileLayer, GeoJSON } from 'react-leaflet';
import countries from '../../../../resources/geo/countries.json';
import inject18n from '../../../../components/i18n';
import ThemeDark from '../../../../components/ThemeDark';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
});

class LocationMiniMap extends Component {
  constructor(props) {
    super(props);
    const countriesAliases = pipe(
      pluck('x_opencti_aliases'),
      filter((n) => n.length > 0),
      map((n) => (head(n).length === 3 ? head(n) : last(n))),
    )(propOr([], 'countries', props));
    this.state = {
      countriesAliases,
    };
  }

  getStyle(feature) {
    if (includes(feature.properties.ISO3, this.state.countriesAliases)) {
      return {
        color: ThemeDark.palette.primary.main,
        weight: 1,
        fillOpacity: 0.2,
      };
    }
    return { fillOpacity: 0, color: 'none' };
  }

  render() {
    const { t, center, zoom } = this.props;
    const mapTileServer = window.MAP_TILE_SERVER !== '%MAP_TILE_SERVER%'
      ? window.MAP_TILE_SERVER
      : 'https://tiles.stadiamaps.com';
    return (
      <div style={{ height: '100%' }}>
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{ marginBottom: 10 }}
        >
          {`${t('Mini map')} (lat. ${center[0]}, long. ${center[1]})`}
        </Typography>
        <Map
          center={center}
          zoom={zoom}
          attributionControl={false}
          zoomControl={false}
        >
          <TileLayer
            url={`${mapTileServer}/tiles/alidade_smooth_dark/{z}/{x}/{y}{r}.png`}
          />
          <GeoJSON data={countries} style={this.getStyle.bind(this)} />
        </Map>
      </div>
    );
  }
}

LocationMiniMap.propTypes = {
  countries: PropTypes.array,
  city: PropTypes.string,
  zoom: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  history: PropTypes.object,
};

export default compose(inject18n, withStyles(styles))(LocationMiniMap);
