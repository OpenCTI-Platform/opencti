import { useEffect, useRef, type ReactNode } from 'react';
import { useTheme } from '@mui/material/styles';
import * as maplibre from 'maplibre-gl';
import type { StyleSpecification } from 'maplibre-gl';
import maplibreglWorker from 'maplibre-gl/dist/maplibre-gl-worker.mjs?worker&url';
import { Protocol } from 'pmtiles';
import Card from '@common/card/Card';
import { APP_BASE_PATH } from '../../../../relay/environment';
import { isValidCoordinates } from '../../../../utils/position.utils';
import useAuth from '../../../../utils/hooks/useAuth';
import allCountries from '../../../../static/geo/countries';

// Configure MapLibre worker URL (must be set before creating any Map)
maplibre.setWorkerUrl(maplibreglWorker);

// Register PMTiles protocol handler
const protocol = new Protocol();
maplibre.addProtocol('pmtiles', protocol.tile);

// Colors from the original filigran-dark3/light3 tile server styles
const DARK_BG = '#1c2f4a';
const DARK_WATER = '#0b1422';
const DARK_ROAD = '#1c8eb6';
const DARK_CASING = '#002850';
const DARK_BOUNDARY = '#0fbcff';
const DARK_LABEL = '#ffffff';

const LIGHT_BG = '#dce0fe';
const LIGHT_WATER = '#ffffff';
const LIGHT_ROAD = '#b4b4b4';
const LIGHT_BOUNDARY = '#001bda';
const LIGHT_LABEL = '#000000';

const WHEEL_ZOOM_RATE = 2;
const DARK_COUNTRY_FILL_OPACITY = 0.1;
const LIGHT_COUNTRY_FILL_OPACITY = 0.5;

export interface Coordinates {
  latitude: number;
  longitude: number;
}

const DEFAULT_CENTER: Coordinates = { latitude: 48.8566969, longitude: 2.3514616 };

export interface MapCountry {
  x_opencti_aliases?: readonly (string | null | undefined)[] | null;
  latitude?: number | null;
  longitude?: number | null;
  color: string;
}

export interface MapMarker {
  position: Coordinates;
  iconUrl: string;
}

export interface MapProps {
  title?: string;
  zoom: number;
  center?: { latitude?: number | null; longitude?: number | null };
  countries?: MapCountry[];
  markers?: MapMarker[];
  children?: ReactNode;
}

// -- Style builder --

// Map platform locale (e.g. 'fr-fr') to PMTiles name field language code
const localeToMapLang = (locale: string): string => {
  // PMTiles tiles use ISO 639-1 codes: en, fr, de, es, it, ja, ko, zh, ru
  return locale.split('-')[0];
};

const buildMapStyle = (pmtilesUrl: string, dark: boolean, lang: string): StyleSpecification => {
  const bg = dark ? DARK_BG : LIGHT_BG;
  const water = dark ? DARK_WATER : LIGHT_WATER;
  const road = dark ? DARK_ROAD : LIGHT_ROAD;
  const casing = dark ? DARK_CASING : LIGHT_ROAD;
  const boundary = dark ? DARK_BOUNDARY : LIGHT_BOUNDARY;
  const labelColor = dark ? DARK_LABEL : LIGHT_LABEL;
  const labelHalo = dark ? DARK_BG : LIGHT_BG;

  const labelField: maplibre.ExpressionSpecification = lang === 'en'
    ? ['coalesce', ['get', 'name:en'], ['get', 'name']]
    : ['coalesce', ['get', `name:${lang}`], ['get', 'name:en'], ['get', 'name']];

  return {
    version: 8,
    sources: {
      protomaps: { type: 'vector', url: pmtilesUrl },
    },
    layers: [
      { id: 'background', type: 'background', paint: { 'background-color': bg } },
      { id: 'earth', type: 'fill', source: 'protomaps', 'source-layer': 'earth', paint: { 'fill-color': bg } },
      { id: 'water', type: 'fill', source: 'protomaps', 'source-layer': 'water', paint: { 'fill-color': water } },
      {
        id: 'roads-casing', type: 'line', source: 'protomaps', 'source-layer': 'roads', minzoom: 7,
        paint: { 'line-color': casing, 'line-width': ['interpolate', ['linear'], ['zoom'], 7, 0.5, 14, 6] },
      },
      {
        id: 'roads', type: 'line', source: 'protomaps', 'source-layer': 'roads', minzoom: 5,
        paint: { 'line-color': road, 'line-width': ['interpolate', ['linear'], ['zoom'], 5, 0.3, 14, 4] },
      },
      {
        id: 'boundaries', type: 'line', source: 'protomaps', 'source-layer': 'boundaries',
        filter: ['==', ['get', 'kind'], 'country'],
        paint: { 'line-color': boundary, 'line-width': ['interpolate', ['linear'], ['zoom'], 1, 0.5, 6, 1.5] },
      },
      {
        id: 'places-country', type: 'symbol', source: 'protomaps', 'source-layer': 'places',
        filter: ['==', ['get', 'kind'], 'country'],
        layout: {
          'text-field': labelField,
          'text-font': ['Roboto Bold'],
          'text-size': ['interpolate', ['linear'], ['zoom'], 2, 10, 6, 14],
        },
        paint: { 'text-color': labelColor, 'text-halo-color': labelColor, 'text-halo-width': 0 },
      },
      {
        id: 'places-city', type: 'symbol', source: 'protomaps', 'source-layer': 'places',
        filter: ['==', ['get', 'kind'], 'locality'], minzoom: 5,
        layout: {
          'text-field': labelField,
          'text-font': ['Roboto Medium'],
          'text-size': ['interpolate', ['linear'], ['zoom'], 5, 10, 10, 13],
        },
        paint: { 'text-color': labelColor, 'text-halo-color': labelHalo, 'text-halo-width': dark ? 0.7 : 0.1 },
      },
    ],
  };
};

// -- Map load helpers --

const addCountryHighlights = (
  map: maplibre.Map,
  countries: MapCountry[],
  dark: boolean,
) => {
  const opacity = dark ? DARK_COUNTRY_FILL_OPACITY : LIGHT_COUNTRY_FILL_OPACITY;
  // Build a map of ISO3 -> color
  const iso3Map = new Map<string, string>();
  for (const country of countries) {
    const aliases = (country.x_opencti_aliases ?? []).filter((a): a is string => !!a);
    for (const iso3 of aliases) {
      iso3Map.set(iso3, country.color);
    }
  }

  if (iso3Map.size === 0) return;

  const features = allCountries.features
    .filter((f) => iso3Map.has(f.properties.ISO3))
    .map((f) => {
      const color = iso3Map.get(f.properties.ISO3)!;
      return { ...f, properties: { ...f.properties, _color: color } };
    });

  if (features.length === 0) return;

  map.addSource('highlighted-countries', {
    type: 'geojson',
    data: { type: 'FeatureCollection', features: features as unknown as GeoJSON.Feature[] },
  });

  map.addLayer({
    id: 'highlighted-countries-fill', type: 'fill', source: 'highlighted-countries',
    paint: { 'fill-color': ['get', '_color'], 'fill-opacity': opacity },
  });

  map.addLayer({
    id: 'highlighted-countries-line', type: 'line', source: 'highlighted-countries',
    paint: { 'line-color': ['get', '_color'], 'line-width': 1 },
  });
};

const addMarkers = (map: maplibre.Map, markers: MapMarker[]) => {
  for (const { position, iconUrl } of markers) {
    const el = document.createElement('div');
    el.style.width = '25px';
    el.style.height = '25px';
    el.style.backgroundImage = `url(${iconUrl})`;
    el.style.backgroundSize = 'contain';
    el.style.backgroundRepeat = 'no-repeat';

    new maplibre.Marker({ element: el })
      .setLngLat([position.longitude, position.latitude])
      .addTo(map);
  }
};

const GeoMap = ({
  title,
  zoom,
  center,
  countries,
  markers,
}: MapProps) => {
  const theme = useTheme();
  const { locale } = useAuth();
  const dark = theme.palette.mode === 'dark';
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!containerRef.current) return undefined;

    const resolvedCenter = [center, markers?.[0]?.position, countries?.[0]].find(isValidCoordinates) ?? DEFAULT_CENTER;
    const mapLang = localeToMapLang(locale);
    const pmtilesUrl = `pmtiles://${window.location.origin}${APP_BASE_PATH}/maps/world.pmtiles`;
    const style = buildMapStyle(pmtilesUrl, dark, mapLang);

    const map = new maplibre.Map({
      container: containerRef.current,
      style,
      center: [resolvedCenter.longitude, resolvedCenter.latitude],
      zoom: zoom - 1,
      attributionControl: false,
      interactive: true,
    });
    map.scrollZoom.setWheelZoomRate(WHEEL_ZOOM_RATE);
    map.on('load', () => {
      if (countries && countries.length > 0) {
        addCountryHighlights(map, countries, dark);
      }
      if (markers && markers.length > 0) {
        addMarkers(map, markers);
      }
    });

    return () => {
      map.remove();
    };
  }, [dark, locale, center, countries, markers, zoom]);

  return (
    <div style={{ width: '100%', height: '100%' }}>
      <Card padding="none" title={title}>
        <div ref={containerRef} style={{ width: '100%', height: '100%', minHeight: 300, borderRadius: 6 }} />
      </Card>
    </div>
  );
};

export default GeoMap;
