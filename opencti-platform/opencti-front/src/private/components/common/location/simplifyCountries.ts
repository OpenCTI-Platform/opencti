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

interface Arc {
  key: string;
  forward: boolean;
  canonical: Position[];
  isShared: boolean;
}

const simplifiedCache = new WeakMap<CountriesCollection, SimplifiedCountries>();

export const polygonsOf = (geometry: CountriesCollection['features'][number]['geometry']): Position[][][] => {
  if (geometry.type === 'Polygon') return [geometry.coordinates];
  if (geometry.type === 'MultiPolygon') return geometry.coordinates;
  return [];
};

const pointKey = (position: Position) => `${position[0]},${position[1]}`;

const keysOf = (loop: Position[]) => {
  const points = loop.map(pointKey);
  const edges = points.map((key, index) => {
    const next = points[(index + 1) % points.length];
    return key < next ? `${key};${next}` : `${next};${key}`;
  });
  return { points, edges };
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

const canonicalLoop = (loop: Position[], keys: string[]) => {
  let minIndex = 0;
  keys.forEach((key, index) => {
    if (key < keys[minIndex]) minIndex = index;
  });
  const rotated = [...loop.slice(minIndex), ...loop.slice(0, minIndex)];
  return [...rotated, rotated[0]];
};

const simplifyPositions = (positions: Position[]): Position[] => {
  const projected = positions.map(([lon, lat]) => L.CRS.EPSG3857.latLngToPoint(L.latLng(lat, lon), SIMPLIFY_ZOOM));
  const positionOf = new Map(projected.map((point, index) => [point, positions[index]]));
  return L.LineUtil.simplify(projected, SIMPLIFY_TOLERANCE_PX).map((point) => positionOf.get(point) ?? positions[0]);
};

export const simplifyCountries = (collection: CountriesCollection): SimplifiedCountries => {
  const cached = simplifiedCache.get(collection);
  if (cached) return cached;

  const rings = collection.features.map((feature) => polygonsOf(feature.geometry));
  const loops = rings.map((polygons) => polygons.map((polygon) => polygon.map(toLoop)));
  const loopKeys = loops.map((polygons) => polygons.map((polygon) => polygon.map(keysOf)));

  const owners = new Map<string, string>();
  const degrees = new Map<string, number>();
  const incrementDegree = (key: string) => degrees.set(key, (degrees.get(key) ?? 0) + 1);
  collection.features.forEach(({ properties }, featureIndex) => {
    for (const polygon of loopKeys[featureIndex]) {
      for (const { points, edges } of polygon) {
        for (const [index, key] of edges.entries()) {
          const current = owners.get(key);
          if (current === undefined) {
            owners.set(key, properties.ISO3);
            incrementDegree(points[index]);
            incrementDegree(points[(index + 1) % points.length]);
          } else if (!current.split('|').includes(properties.ISO3)) {
            owners.set(key, [...current.split('|'), properties.ISO3].sort().join('|'));
          }
        }
      }
    }
  });

  const toArc = (points: Position[], edgeOwners: string): Arc => {
    const isClosed = pointKey(points[0]) === pointKey(points[points.length - 1]);
    const forward = isClosed
      ? pointKey(points[1]) < pointKey(points[points.length - 2])
      : pointKey(points[0]) < pointKey(points[points.length - 1]);
    const canonical = forward ? points : [...points].reverse();
    const key = `${edgeOwners}|${canonical.length}|${pointKey(canonical[0])}|${pointKey(canonical[1])}|${pointKey(canonical[canonical.length - 1])}`;
    return { key, forward, canonical, isShared: edgeOwners.includes('|') };
  };

  const arcsOf = (loop: Position[], { points, edges }: { points: string[]; edges: string[] }): Arc[] | null => {
    if (loop.length < 3) return null;
    const ownersOf = (index: number) => owners.get(edges[index]) ?? '';
    const cuts = points.flatMap((key, index) => ((degrees.get(key) ?? 0) >= 3 ? [index] : []));
    if (cuts.length === 0) return [toArc(canonicalLoop(loop, points), ownersOf(0))];
    return cuts.map((cut, cutIndex) => {
      const next = cuts[(cutIndex + 1) % cuts.length];
      const length = (next - cut + loop.length) % loop.length || loop.length;
      return toArc(Array.from({ length: length + 1 }, (_, offset) => loop[(cut + offset) % loop.length]), ownersOf(cut));
    });
  };

  const simplifiedArcs = new Map<string, Position[]>();
  const simplifiedPointsOf = (arc: Arc) => {
    let simplified = simplifiedArcs.get(arc.key);
    if (!simplified) {
      simplified = simplifyPositions(arc.canonical);
      simplifiedArcs.set(arc.key, simplified);
    }
    return simplified;
  };

  const assemble = (arcs: Arc[], pointsOf: (arc: Arc) => Position[]) => {
    const assembled: Position[] = [];
    for (const arc of arcs) {
      const points = arc.forward ? pointsOf(arc) : [...pointsOf(arc)].reverse();
      assembled.push(...(assembled.length === 0 ? points : points.slice(1)));
    }
    return assembled;
  };

  const loopArcs = loops.map((polygons, featureIndex) => polygons.map((polygon, polygonIndex) => (
    polygon.map((loop, ringIndex) => arcsOf(loop, loopKeys[featureIndex][polygonIndex][ringIndex]))
  )));

  const preservedArcs = new Set<string>();
  for (const arcs of loopArcs.flat(2)) {
    if (arcs && assemble(arcs, simplifiedPointsOf).length < MIN_RING_POSITIONS) {
      arcs.forEach((arc) => preservedArcs.add(arc.key));
    }
  }
  const finalPointsOf = (arc: Arc) => (preservedArcs.has(arc.key) ? arc.canonical : simplifiedPointsOf(arc));

  const borders: Position[][] = [];
  const emittedBorders = new Set<string>();
  for (const arc of loopArcs.flat(3)) {
    if (arc && arc.isShared && !emittedBorders.has(arc.key)) {
      emittedBorders.add(arc.key);
      borders.push(finalPointsOf(arc));
    }
  }

  const countries: CountriesCollection = {
    ...collection,
    features: collection.features.map((feature, featureIndex) => {
      const polygons = loopArcs[featureIndex].map((polygon, polygonIndex) => (
        polygon.map((arcs, ringIndex) => (arcs ? assemble(arcs, finalPointsOf) : rings[featureIndex][polygonIndex][ringIndex]))
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
