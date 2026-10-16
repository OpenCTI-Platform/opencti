import L from 'leaflet';
import type { Position } from 'geojson';
import type { CountriesCollection } from './countries';

const SIMPLIFY_ZOOM = 6;
const SIMPLIFY_TOLERANCE_PX = 1;
const MIN_RING_POSITIONS = 4;

export interface SimplifiedCountries {
  countries: CountriesCollection;
  borders: Position[][];
}

const simplifiedCache = new WeakMap<CountriesCollection, SimplifiedCountries>();

export const polygonsOf = (geometry: CountriesCollection['features'][number]['geometry']): Position[][][] => {
  if (geometry.type === 'Polygon') return [geometry.coordinates];
  if (geometry.type === 'MultiPolygon') return geometry.coordinates;
  return [];
};

const pointKey = (position: Position) => `${position[0]},${position[1]}`;

const edgeKeysOf = (loop: Position[]) => {
  const pointKeys = loop.map(pointKey);
  return pointKeys.map((key, index) => {
    const next = pointKeys[(index + 1) % pointKeys.length];
    return key < next ? `${key};${next}` : `${next};${key}`;
  });
};

const toLoop = (ring: Position[]) => {
  const loop: Position[] = [];
  for (const position of ring) {
    const last = loop[loop.length - 1];
    if (!last || last[0] !== position[0] || last[1] !== position[1]) loop.push(position);
  }
  const first = loop[0];
  const last = loop[loop.length - 1];
  if (loop.length > 1 && first[0] === last[0] && first[1] === last[1]) loop.pop();
  return loop;
};

const canonicalLoop = (loop: Position[]) => {
  const keys = loop.map(pointKey);
  let minIndex = 0;
  keys.forEach((key, index) => {
    if (key < keys[minIndex]) minIndex = index;
  });
  const rotated = [...loop.slice(minIndex), ...loop.slice(0, minIndex)];
  return [...rotated, rotated[0]];
};

const simplifyPositions = (positions: Position[]): Position[] => {
  const projected = positions.map(([lon, lat]) => L.CRS.EPSG3857.latLngToPoint(L.latLng(lat, lon), SIMPLIFY_ZOOM));
  return L.LineUtil.simplify(projected, SIMPLIFY_TOLERANCE_PX).map((point) => {
    const { lat, lng } = L.CRS.EPSG3857.pointToLatLng(point, SIMPLIFY_ZOOM);
    return [lng, lat];
  });
};

export const simplifyCountries = (collection: CountriesCollection): SimplifiedCountries => {
  const cached = simplifiedCache.get(collection);
  if (cached) return cached;

  const rings = collection.features.map((feature) => polygonsOf(feature.geometry));
  const loops = rings.map((polygons) => polygons.map((polygon) => polygon.map(toLoop)));
  const loopEdges = loops.map((polygons) => polygons.map((polygon) => polygon.map(edgeKeysOf)));

  const owners = new Map<string, string>();
  collection.features.forEach(({ properties }, featureIndex) => {
    for (const polygon of loopEdges[featureIndex]) {
      for (const edges of polygon) {
        for (const key of edges) {
          const current = owners.get(key);
          if (current === undefined) {
            owners.set(key, properties.ISO3);
          } else if (!current.split('|').includes(properties.ISO3)) {
            owners.set(key, [...current.split('|'), properties.ISO3].sort().join('|'));
          }
        }
      }
    }
  });

  const arcs = new Map<string, Position[]>();
  const borders: Position[][] = [];

  const simplifyArc = (points: Position[], edgeOwners: string) => {
    const isClosed = pointKey(points[0]) === pointKey(points[points.length - 1]);
    const forward = isClosed
      ? pointKey(points[1]) < pointKey(points[points.length - 2])
      : pointKey(points[0]) < pointKey(points[points.length - 1]);
    const canonical = forward ? points : [...points].reverse();
    const key = `${edgeOwners}|${canonical.length}|${pointKey(canonical[0])}|${pointKey(canonical[1])}|${pointKey(canonical[canonical.length - 1])}`;
    let simplified = arcs.get(key);
    if (!simplified) {
      simplified = simplifyPositions(canonical);
      if (isClosed && simplified.length < MIN_RING_POSITIONS) simplified = canonical;
      arcs.set(key, simplified);
      if (edgeOwners.includes('|')) borders.push(simplified);
    }
    return forward ? simplified : [...simplified].reverse();
  };

  const simplifyLoop = (loop: Position[], edges: string[], ring: Position[]) => {
    if (loop.length < 3) return ring;
    const labels = edges.map((key) => owners.get(key) ?? '');
    const cuts = labels.flatMap((label, index) => (label === labels[(index - 1 + loop.length) % loop.length] ? [] : [index]));
    if (cuts.length === 0) {
      const simplified = simplifyArc(canonicalLoop(loop), labels[0]);
      return simplified.length < MIN_RING_POSITIONS ? ring : simplified;
    }
    const simplified: Position[] = [];
    cuts.forEach((cut, cutIndex) => {
      const next = cuts[(cutIndex + 1) % cuts.length];
      const length = (next - cut + loop.length) % loop.length || loop.length;
      const arc = Array.from({ length: length + 1 }, (_, offset) => loop[(cut + offset) % loop.length]);
      const part = simplifyArc(arc, labels[cut]);
      simplified.push(...(simplified.length === 0 ? part : part.slice(1)));
    });
    return simplified.length < MIN_RING_POSITIONS ? ring : simplified;
  };

  const countries: CountriesCollection = {
    ...collection,
    features: collection.features.map((feature, featureIndex) => {
      const polygons = loops[featureIndex].map((polygon, polygonIndex) => (
        polygon.map((loop, ringIndex) => simplifyLoop(loop, loopEdges[featureIndex][polygonIndex][ringIndex], rings[featureIndex][polygonIndex][ringIndex]))
      ));
      if (feature.geometry.type === 'Polygon') {
        return { ...feature, geometry: { ...feature.geometry, coordinates: polygons[0] } };
      }
      if (feature.geometry.type === 'MultiPolygon') {
        return { ...feature, geometry: { ...feature.geometry, coordinates: polygons } };
      }
      return feature;
    }),
  };

  const result = { countries, borders };
  simplifiedCache.set(collection, result);
  return result;
};
