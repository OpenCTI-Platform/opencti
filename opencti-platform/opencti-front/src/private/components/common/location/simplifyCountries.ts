import L from 'leaflet';
import type { Position } from 'geojson';
import type { CountriesCollection } from './countries';

const SIMPLIFY_ZOOM = 6;
const SIMPLIFY_TOLERANCE_PX = 1;
const MIN_RING_POSITIONS = 4;

const simplifiedCache = new WeakMap<CountriesCollection, CountriesCollection>();

export const simplifyRing = (ring: Position[]): Position[] => {
  const projected = ring.map(([lon, lat]) => L.CRS.EPSG3857.latLngToPoint(L.latLng(lat, lon), SIMPLIFY_ZOOM));
  const simplified = L.LineUtil.simplify(projected, SIMPLIFY_TOLERANCE_PX);
  if (simplified.length < MIN_RING_POSITIONS) return ring;
  return simplified.map((point) => {
    const { lat, lng } = L.CRS.EPSG3857.pointToLatLng(point, SIMPLIFY_ZOOM);
    return [lng, lat];
  });
};

export const simplifyCountries = (collection: CountriesCollection): CountriesCollection => {
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
