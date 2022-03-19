import React, { useContext } from 'react';
import * as PropTypes from 'prop-types';
import { compose, flatten, propOr, pluck, includes, uniq, pipe } from 'ramda';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { MapContainer, TileLayer, GeoJSON, Marker } from 'react-leaflet';
import L from 'leaflet';
import countries from '../../../../resources/geo/countries.json';
import inject18n from '../../../../components/i18n';
import { UserContext } from '../../../../utils/Security';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 8,
  },
});

const pointerIcon = (dark = true) => new L.Icon({
  iconUrl: `/static/city_${dark ? 'dark' : 'light'}.png`,
  iconRetinaUrl: `/static/city_${dark ? 'dark' : 'light'}.png`,
  iconAnchor: [5, 55],
  popupAnchor: [10, -44],
  iconSize: [25, 25],
});

const LocationMiniMap = (props) => {
  const { settings } = useContext(UserContext);
  const countriesAliases = pipe(
    pluck('x_opencti_aliases'),
    flatten,
    uniq,
  )(propOr([], 'countries', props));
  const getStyle = (feature) => {
    if (includes(feature.properties.ISO3, countriesAliases)) {
      return {
        color: props.theme.palette.primary.main,
        weight: 1,
        fillOpacity: 0.1,
      };
    }
    return { fillOpacity: 0, color: 'none' };
  };
  const { t, center, zoom, classes, theme, city } = props;
  const position = city && city.latitude ? [city.latitude, city.longitude] : null;
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true} style={{ marginBottom: 10 }}>
        {`${t('Mini map')} (lat. ${center[0]}, long. ${center[1]})`}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <MapContainer
          center={center}
          zoom={zoom}
          attributionControl={false}
          zoomControl={false}
        >
          <TileLayer
            url={
              theme.palette.mode === 'light'
                ? settings.platform_map_tile_server_light
                : settings.platform_map_tile_server_dark
            }
          />
          <GeoJSON data={countries} style={getStyle} />
          {position ? (
            <Marker
              position={position}
              icon={pointerIcon(theme.palette.mode === 'dark')}
            />
          ) : (
            ''
          )}
        </MapContainer>
      </Paper>
    </div>
  );
};

LocationMiniMap.propTypes = {
  countries: PropTypes.array,
  city: PropTypes.string,
  zoom: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(LocationMiniMap);
