import React, { useContext } from 'react';
import * as PropTypes from 'prop-types';
import { compose, flatten, propOr, pluck, uniq, pipe } from 'ramda';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { MapContainer, TileLayer, GeoJSON, Marker } from 'react-leaflet';
import L from 'leaflet';
import countries from '../../../../static/geo/countries.json';
import inject18n from '../../../../components/i18n';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { fileUri } from '../../../../relay/environment';
import CityDark from '../../../../static/images/leaflet/city_dark.png';
import MarkerDark from '../../../../static/images/leaflet/marker_dark.png';
import CityLight from '../../../../static/images/leaflet/city_light.png';
import MarkerLight from '../../../../static/images/leaflet/marker_light.png';

const styles = (theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: 0,
    borderRadius: 8,
  },
});

const cityIcon = (dark = true) => new L.Icon({
  iconUrl: dark ? fileUri(CityDark) : fileUri(CityLight),
  iconRetinaUrl: dark ? fileUri(CityDark) : fileUri(CityLight),
  iconAnchor: [12, 12],
  popupAnchor: [0, -12],
  iconSize: [25, 25],
});

const positionIcon = (dark = true) => new L.Icon({
  iconUrl: dark ? fileUri(MarkerDark) : fileUri(MarkerLight),
  iconRetinaUrl: dark ? fileUri(MarkerDark) : fileUri(MarkerLight),
  iconAnchor: [12, 12],
  popupAnchor: [0, -12],
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
    if (countriesAliases.includes(feature.properties.ISO3)) {
      return {
        color: props.theme.palette.primary.main,
        weight: 1,
        fillOpacity: 0.1,
      };
    }
    return { fillOpacity: 0, color: 'none' };
  };
  const { t, center, zoom, classes, theme, city, position } = props;
  let mapPosition = null;
  if (city && city.latitude && city.longitude) {
    mapPosition = [city.latitude, city.longitude];
  } else if (position && position.latitude && position.longitude) {
    mapPosition = [position.latitude, position.longitude];
  }
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true} style={{ marginBottom: 10 }}>
        {`${t('Mini map')} (lat. ${center[0]}, long. ${center[1]})`}
      </Typography>
      <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
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
          {mapPosition && (
            <Marker
              position={mapPosition}
              icon={
                city
                  ? cityIcon(theme.palette.mode === 'dark')
                  : positionIcon(theme.palette.mode === 'dark')
              }
            />
          )}
        </MapContainer>
      </Paper>
    </div>
  );
};

LocationMiniMap.propTypes = {
  countries: PropTypes.array,
  city: PropTypes.object,
  zoom: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  navigate: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(LocationMiniMap);
