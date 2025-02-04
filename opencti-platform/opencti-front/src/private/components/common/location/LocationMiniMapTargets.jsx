import React, { useContext } from 'react';
import { GeoJSON, MapContainer, Marker, TileLayer } from 'react-leaflet';
import L from 'leaflet';
import { useTheme } from '@mui/material/styles';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { fileUri } from '../../../../relay/environment';
import CityOrange from '../../../../static/images/leaflet/city_orange.png';
import { usePublicSettings } from '../../../../public/PublicSettingsProvider';
import allCountries from '../../../../static/geo/countries.json';

const colors = [
  '#fff59d',
  '#ffe082',
  '#ffb300',
  '#ffb74d',
  '#fb8c00',
  '#d95f00',
  '#e64a19',
  '#f44336',
  '#d32f2f',
  '#b71c1c',
];

const pointerIcon = new L.Icon({
  iconUrl: fileUri(CityOrange),
  iconRetinaUrl: fileUri(CityOrange),
  iconAnchor: [5, 55],
  popupAnchor: [10, -44],
  iconSize: [25, 25],
});

const LocationMiniMapTargets = ({ center, zoom, cities, countries }) => {
  const theme = useTheme();

  const { settings: privateSettings } = useContext(UserContext);
  const { settings: publicSettings } = usePublicSettings();
  const settings = privateSettings ?? publicSettings;

  const countriesAliases = (countries ?? []).flatMap((c) => {
    if (!c) return [];
    return c.x_opencti_aliases ?? [];
  });

  const locatedCities = (cities ?? []).filter((c) => c.latitude && c.longitude);

  const getStyle = (feature) => {
    if (countriesAliases.includes(feature.properties.ISO3)) {
      const country = countries.find(({ x_opencti_aliases }) => {
        return (x_opencti_aliases ?? []).includes(feature.properties.ISO3);
      });
      return {
        color: country.level ? colors[country.level] : colors[5],
        weight: 1,
        fillOpacity: theme.palette.mode === 'light' ? 0.5 : 0.1,
      };
    }
    return { fillOpacity: 0, color: 'none' };
  };

  const tileServer = theme.palette.mode === 'light'
    ? settings.platform_map_tile_server_light
    : settings.platform_map_tile_server_dark;

  return (
    <div style={{ width: '100%', height: '100%' }}>
      <MapContainer
        // introducing uniqueness in component rendering
        // it is a bug workaround that prevents the component from rendering
        //
        // to be removed when bug is fixed
        // more info on the bug and its fix: https://github.com/PaulLeCam/react-leaflet/pull/1073
        key={new Date().getTime()}
        center={center}
        zoom={zoom}
        attributionControl={false}
        zoomControl={false}
      >
        <TileLayer url={tileServer} />
        <GeoJSON data={allCountries} style={getStyle} />
        {locatedCities.map((city) => {
          const position = [city.latitude, city.longitude];
          return (
            <Marker key={city.id} position={position} icon={pointerIcon} />
          );
        })}
      </MapContainer>
    </div>
  );
};

export default LocationMiniMapTargets;
