import { useMemo } from 'react';
import CityOrange from '../../../../static/images/map/city_orange.png';
import GeoMap, { Coordinates, type MapCountry, type MapMarker } from './GeoMap';
import { isValidCoordinates } from '../../../../utils/position.utils';

const THREAT_COLORS = [
  '#fff59d', '#ffe082', '#ffb300', '#ffb74d', '#fb8c00',
  '#d95f00', '#e64a19', '#f44336', '#d32f2f', '#b71c1c',
];

interface City {
  id?: string;
  latitude?: number | null;
  longitude?: number | null;
}

interface Country {
  x_opencti_aliases?: readonly (string | null | undefined)[] | null;
  level?: number;
}

interface LocationMiniMapTargetsProps {
  title?: string;
  zoom: number;
  center?: { latitude?: number | null; longitude?: number | null };
  countries?: Country[];
  cities?: (City | null | undefined)[];
}

const LocationMiniMapTargets = ({ title, zoom, center, countries = [], cities }: LocationMiniMapTargetsProps) => {
  const coloredCountries: MapCountry[] = useMemo(() => countries.map((c) => ({
    x_opencti_aliases: c.x_opencti_aliases,
    color: c.level ? THREAT_COLORS[c.level] : THREAT_COLORS[5],
  })), [countries]);

  const markers: MapMarker[] = useMemo(() => (
    (cities ?? [])
      .filter((c): c is Coordinates => isValidCoordinates(c))
      .map((coordinates) => ({ position: coordinates, iconUrl: CityOrange }))
  ), [cities]);

  return (
    <GeoMap
      title={title}
      zoom={zoom}
      center={center}
      countries={coloredCountries}
      markers={markers}
    />
  );
};

export default LocationMiniMapTargets;
