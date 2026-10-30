import { useMemo } from 'react';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import CityDark from '../../../../static/images/map/city_dark.png';
import CityLight from '../../../../static/images/map/city_light.png';
import MarkerDark from '../../../../static/images/map/marker_dark.png';
import MarkerLight from '../../../../static/images/map/marker_light.png';
import { isValidCoordinates } from '../../../../utils/position.utils';
import GeoMap, { type MapCountry, type MapMarker } from './GeoMap';

interface LocationMiniMapProps {
  zoom?: number;
  center?: { latitude?: number | null; longitude?: number | null };
  location?: { latitude?: number | null; longitude?: number | null };
  locationType?: 'city' | 'position';
  countries?: {
    x_opencti_aliases?: readonly (string | null | undefined)[] | null;
    latitude?: number | null;
    longitude?: number | null;
  }[];
}

const LocationMiniMap = ({ zoom, center, location, locationType = 'city', countries = [] }: LocationMiniMapProps) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const dark = theme.palette.mode === 'dark';

  const coloredCountries: MapCountry[] = useMemo(() => (
    countries.map((c) => ({ ...c, color: theme.palette.primary.main }))
  ), [countries, theme.palette.primary.main]);

  const markers = useMemo((): MapMarker[] | undefined => {
    if (isValidCoordinates(location)) {
      const iconUrl = locationType === 'city'
        ? (dark ? CityDark : CityLight)
        : (dark ? MarkerDark : MarkerLight);
      return [{ position: location, iconUrl }];
    } else {
      return [];
    }
  }, [location, locationType, dark]);

  return (
    <GeoMap
      title={t_i18n('Mini map')}
      zoom={zoom ?? 4}
      center={center}
      countries={coloredCountries}
      markers={markers}
    />
  );
};

export default LocationMiniMap;
