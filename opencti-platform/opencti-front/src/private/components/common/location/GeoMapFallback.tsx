import { useEffect, useRef } from 'react';
import { useTheme } from '@mui/material/styles';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import type { Position } from 'geojson';
import { isValidCoordinates } from '../../../../utils/position.utils';
import { loadCountries, type CountriesCollection } from './countries';
import type { Coordinates, MapProps } from './GeoMap';

const DARK = { bg: '#1c2f4a', water: '#0b1422', boundary: '#0fbcff', fillOpacity: 0.1 };
const LIGHT = { bg: '#dce0fe', water: '#ffffff', boundary: '#001bda', fillOpacity: 0.5 };
const DEFAULT_CENTER: Coordinates = { latitude: 48.8566969, longitude: 2.3514616 };
const WORLD_BOUNDS: L.LatLngBoundsExpression = [[-85.051129, -180], [85.051129, 180]];
const MARKER_SIZE = 25;
const MIN_HEIGHT = 300;
const SIMPLIFY_ZOOM = 6;
const SIMPLIFY_TOLERANCE_PX = 1;

const simplifiedCache = new WeakMap<CountriesCollection, CountriesCollection>();

const simplifyRing = (ring: Position[]): Position[] => {
  const projected = ring.map(([lon, lat]) => L.CRS.EPSG3857.latLngToPoint(L.latLng(lat, lon), SIMPLIFY_ZOOM));
  return L.LineUtil.simplify(projected, SIMPLIFY_TOLERANCE_PX).map((point) => {
    const { lat, lng } = L.CRS.EPSG3857.pointToLatLng(point, SIMPLIFY_ZOOM);
    return [lng, lat];
  });
};

const simplifyCountries = (collection: CountriesCollection): CountriesCollection => {
  const cached = simplifiedCache.get(collection);
  if (cached) return cached;
  const simplified: CountriesCollection = {
    ...collection,
    features: collection.features.map((feature) => {
      const { geometry } = feature;
      if (geometry.type === 'Polygon') {
        return { ...feature, geometry: { ...geometry, coordinates: geometry.coordinates.map(simplifyRing) } };
      }
      if (geometry.type === 'MultiPolygon') {
        return { ...feature, geometry: { ...geometry, coordinates: geometry.coordinates.map((polygon) => polygon.map(simplifyRing)) } };
      }
      return feature;
    }),
  };
  simplifiedCache.set(collection, simplified);
  return simplified;
};

const boundaryWidth = (leafletZoom: number) => {
  const z = leafletZoom - 1;
  if (z <= 1) return 0.5;
  if (z >= 6) return 1.5;
  return 0.5 + (z - 1) / 5;
};

type GeoMapFallbackProps = Pick<MapProps, 'zoom' | 'center' | 'countries' | 'markers'>;

const GeoMapFallback = ({
  zoom,
  center,
  countries,
  markers,
}: GeoMapFallbackProps) => {
  const theme = useTheme();
  const dark = theme.palette.mode === 'dark';
  const colors = dark ? DARK : LIGHT;
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return undefined;

    const resolvedCenter = [center, markers?.[0]?.position, countries?.[0]].find(isValidCoordinates) ?? DEFAULT_CENTER;
    const map = L.map(container, {
      center: [resolvedCenter.latitude, resolvedCenter.longitude],
      zoom,
      minZoom: 1,
      maxZoom: 12,
      zoomSnap: 0.25,
      wheelPxPerZoomLevel: 120,
      maxBounds: WORLD_BOUNDS,
      maxBoundsViscosity: 1,
      zoomControl: false,
      attributionControl: false,
      renderer: L.svg({ padding: 0.5 }),
    });

    const colorByIso3 = new Map<string, string>();
    for (const country of countries ?? []) {
      for (const alias of country.x_opencti_aliases ?? []) {
        if (alias) colorByIso3.set(alias, country.color);
      }
    }

    let base: L.GeoJSON | null = null;
    map.on('zoomend', () => base?.setStyle({ weight: boundaryWidth(map.getZoom()) }));

    let released = false;
    loadCountries()
      .then((fullCollection) => {
        if (released) return;
        const collection = simplifyCountries(fullCollection);
        base = L.geoJSON(collection, {
          interactive: false,
          style: { color: colors.boundary, weight: boundaryWidth(map.getZoom()), fillColor: colors.bg, fillOpacity: 1, lineJoin: 'round' },
        }).addTo(map);
        if (colorByIso3.size > 0) {
          L.geoJSON(collection, {
            interactive: false,
            filter: (feature) => colorByIso3.has(feature.properties.ISO3),
            style: (feature) => {
              const color = feature ? colorByIso3.get(feature.properties.ISO3) : undefined;
              return { color, weight: 1, fillColor: color, fillOpacity: colors.fillOpacity, lineJoin: 'round' };
            },
          }).addTo(map);
        }
      })
      .catch(() => {});

    for (const { position, iconUrl } of markers ?? []) {
      L.marker([position.latitude, position.longitude], {
        icon: L.icon({ iconUrl, iconSize: [MARKER_SIZE, MARKER_SIZE], iconAnchor: [MARKER_SIZE / 2, MARKER_SIZE / 2] }),
        interactive: false,
        keyboard: false,
      }).addTo(map);
    }

    const observer = new ResizeObserver(() => map.invalidateSize());
    observer.observe(container);

    return () => {
      released = true;
      observer.disconnect();
      map.remove();
    };
  }, [dark, center, countries, markers, zoom]);

  return (
    <div
      ref={containerRef}
      aria-label="Map"
      style={{ width: '100%', height: '100%', minHeight: MIN_HEIGHT, borderRadius: 6, background: colors.water }}
    />
  );
};

export default GeoMapFallback;
