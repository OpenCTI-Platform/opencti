import { useEffect, useRef, useState } from 'react';
import { useTheme } from '@mui/material/styles';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import type { MultiLineString, Position } from 'geojson';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import { isValidCoordinates } from '../../../../utils/position.utils';
import { loadCountries, type CountriesCollection } from './countries';
import type { Coordinates, MapProps } from './GeoMap';
import { polygonsOf, simplifyCountries } from './simplifyCountries';

const DARK = { bg: '#1c2f4a', water: '#0b1422', boundary: '#0fbcff', label: '#ffffff', fillOpacity: 0.1 };
const LIGHT = { bg: '#dce0fe', water: '#ffffff', boundary: '#001bda', label: '#000000', fillOpacity: 0.5 };
const DEFAULT_CENTER: Coordinates = { latitude: 48.8566969, longitude: 2.3514616 };
const WORLD_BOUNDS: L.LatLngBoundsExpression = [[-85.051129, -180], [85.051129, 180]];
const MARKER_SIZE = 25;
const MIN_HEIGHT = 300;
const LABEL_PANE = 'country-labels';
const LABEL_FONT_SIZE = 11;
const LABEL_LINE_HEIGHT = 14;
const LABEL_MAX_WIDTH = 10 * LABEL_FONT_SIZE;
const LABEL_SPACING = 4;
const LABEL_MIN_COUNTRY_AREA_PX = 1500;
const LABEL_ALL_COUNTRIES_MAX_VIEW_KM = 2000;
const SHARED_GEOMETRY_OPTIONS: L.PolylineOptions = { smoothFactor: 0 };

interface LabelCandidate {
  iso3: string;
  name: string;
  anchor: L.LatLng;
  area: number;
  largestPolygonArea: number;
}

interface LabelLayout {
  text: string;
  width: number;
  height: number;
}

const labelCandidatesCache = new WeakMap<CountriesCollection, LabelCandidate[]>();
const labelLayoutCache = new Map<string, LabelLayout>();
let measureContext: CanvasRenderingContext2D | null = null;

const projectRing = (ring: Position[]) => ring.map(([lon, lat]) => L.CRS.EPSG3857.latLngToPoint(L.latLng(lat, lon), 0));

const ringArea = (points: L.Point[]) => {
  let doubleArea = 0;
  points.forEach((point, index) => {
    const next = points[(index + 1) % points.length];
    doubleArea += point.x * next.y - next.x * point.y;
  });
  return Math.abs(doubleArea) / 2;
};

const toLabelCandidates = (collection: CountriesCollection): LabelCandidate[] => {
  const cached = labelCandidatesCache.get(collection);
  if (cached) return cached;
  const byIso3 = new Map<string, LabelCandidate>();
  for (const { geometry, properties } of collection.features.filter((feature) => feature.properties.NAME && feature.properties.ISO2 !== '')) {
    const hasLabelPoint = Number.isFinite(properties.LAT) && Number.isFinite(properties.LON);
    for (const [outer, ...holes] of polygonsOf(geometry)) {
      const outerPoints = projectRing(outer);
      const polygonArea = ringArea(outerPoints) - holes.reduce((total, hole) => total + ringArea(projectRing(hole)), 0);
      const anchor = hasLabelPoint ? L.latLng(properties.LAT, properties.LON) : L.CRS.EPSG3857.pointToLatLng(L.bounds(outerPoints).getCenter(), 0);
      const current = byIso3.get(properties.ISO3);
      if (!current) {
        byIso3.set(properties.ISO3, { iso3: properties.ISO3, name: properties.NAME, anchor, area: polygonArea, largestPolygonArea: polygonArea });
      } else {
        current.area += polygonArea;
        if (polygonArea > current.largestPolygonArea) {
          current.largestPolygonArea = polygonArea;
          current.name = properties.NAME;
          current.anchor = anchor;
        }
      }
    }
  }
  const candidates = [...byIso3.values()];
  labelCandidatesCache.set(collection, candidates);
  return candidates;
};

const measureText = (text: string, font: string) => {
  measureContext ??= document.createElement('canvas').getContext('2d');
  if (!measureContext) return text.length * LABEL_FONT_SIZE * 0.6;
  measureContext.font = font;
  return measureContext.measureText(text).width;
};

const layoutLabel = (name: string, font: string): LabelLayout => {
  const key = `${font}|${name}`;
  const cached = labelLayoutCache.get(key);
  if (cached) return cached;
  const lines: string[] = [];
  for (const word of name.split(/\s+/)) {
    const last = lines[lines.length - 1];
    if (last !== undefined && measureText(`${last} ${word}`, font) <= LABEL_MAX_WIDTH) {
      lines[lines.length - 1] = `${last} ${word}`;
    } else {
      lines.push(word);
    }
  }
  const layout = {
    text: lines.join('\n'),
    width: Math.max(...lines.map((line) => measureText(line, font))),
    height: lines.length * LABEL_LINE_HEIGHT,
  };
  labelLayoutCache.set(key, layout);
  return layout;
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
  const { t_i18n } = useFormatter();
  const dark = theme.palette.mode === 'dark';
  const colors = dark ? DARK : LIGHT;
  const fontFamily = theme.typography.fontFamily ?? 'sans-serif';
  const containerRef = useRef<HTMLDivElement>(null);
  const [isLoadFailed, setIsLoadFailed] = useState(false);

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
    const labelPane = map.createPane(LABEL_PANE);
    labelPane.style.zIndex = '450';
    labelPane.style.pointerEvents = 'none';
    const labels = L.layerGroup().addTo(map);

    const colorByIso3 = new Map<string, string>();
    for (const country of countries ?? []) {
      for (const alias of country.x_opencti_aliases ?? []) {
        if (alias) colorByIso3.set(alias, country.color);
      }
    }
    const markerPositions = (markers ?? []).map(({ position }) => L.latLng(position.latitude, position.longitude));

    let borderLayer: L.GeoJSON | null = null;
    let candidates: LabelCandidate[] | null = null;

    const renderLabels = () => {
      if (!candidates) return;
      const currentZoom = map.getZoom();
      const scale = 2 ** currentZoom;
      const font = `600 ${LABEL_FONT_SIZE}px ${fontFamily}`;
      const placed = markerPositions.map((position) => {
        const point = map.project(position, currentZoom);
        return L.bounds([point.x - MARKER_SIZE / 2, point.y - MARKER_SIZE / 2], [point.x + MARKER_SIZE / 2, point.y + MARKER_SIZE / 2]);
      });
      const { x: width, y: height } = map.getSize();
      const visibleWidthKm = map.distance(map.containerPointToLatLng([0, height / 2]), map.containerPointToLatLng([width, height / 2])) / 1000;
      const labelsAllCountries = visibleWidthKm <= LABEL_ALL_COUNTRIES_MAX_VIEW_KM;
      const ordered = candidates
        .filter((candidate) => labelsAllCountries || candidate.area * scale * scale >= LABEL_MIN_COUNTRY_AREA_PX)
        .sort((a, b) => Number(colorByIso3.has(b.iso3)) - Number(colorByIso3.has(a.iso3)) || b.area - a.area);
      labels.clearLayers();
      for (const candidate of ordered) {
        const { text, width, height } = layoutLabel(candidate.name, font);
        const point = map.project(candidate.anchor, currentZoom);
        const box = L.bounds(
          [point.x - width / 2 - LABEL_SPACING, point.y - height / 2 - LABEL_SPACING],
          [point.x + width / 2 + LABEL_SPACING, point.y + height / 2 + LABEL_SPACING],
        );
        if (!placed.some((other) => other.intersects(box))) {
          placed.push(box);
          const element = document.createElement('span');
          element.textContent = text;
          Object.assign(element.style, {
            display: 'block',
            whiteSpace: 'pre',
            textAlign: 'center',
            font,
            lineHeight: `${LABEL_LINE_HEIGHT}px`,
            color: colors.label,
            textShadow: `0 0 3px ${colors.bg}, 0 0 3px ${colors.bg}`,
          });
          L.marker(candidate.anchor, {
            pane: LABEL_PANE,
            interactive: false,
            keyboard: false,
            icon: L.divIcon({ className: '', html: element, iconSize: [width, height], iconAnchor: [width / 2, height / 2] }),
          }).addTo(labels);
        }
      }
    };

    map.on('zoomend', () => {
      borderLayer?.setStyle({ weight: boundaryWidth(map.getZoom()) });
      renderLabels();
    });

    let released = false;
    loadCountries()
      .then((fullCollection) => {
        if (released) return;
        const { countries: collection, borders } = simplifyCountries(fullCollection);
        L.geoJSON(collection, {
          ...SHARED_GEOMETRY_OPTIONS,
          interactive: false,
          style: { stroke: false, fillColor: colors.bg, fillOpacity: 1 },
        }).addTo(map);
        const borderLines: MultiLineString = { type: 'MultiLineString', coordinates: borders };
        borderLayer = L.geoJSON(borderLines, {
          ...SHARED_GEOMETRY_OPTIONS,
          interactive: false,
          style: { color: colors.boundary, weight: boundaryWidth(map.getZoom()), lineJoin: 'round' },
        }).addTo(map);
        if (colorByIso3.size > 0) {
          L.geoJSON(collection, {
            ...SHARED_GEOMETRY_OPTIONS,
            interactive: false,
            filter: (feature) => colorByIso3.has(feature.properties.ISO3),
            style: (feature) => {
              const color = feature ? colorByIso3.get(feature.properties.ISO3) : undefined;
              return { color, weight: 1, fillColor: color, fillOpacity: colors.fillOpacity, lineJoin: 'round' };
            },
          }).addTo(map);
        }
        candidates = toLabelCandidates(collection);
        renderLabels();
      })
      .catch(() => {
        if (!released) setIsLoadFailed(true);
      });
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
  }, [dark, fontFamily, center, countries, markers, zoom, isLoadFailed]);

  if (isLoadFailed) {
    return (
      <div
        key="load-failed"
        style={{
          minHeight: MIN_HEIGHT,
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 8,
        }}
      >
        <p>{t_i18n('Failed to load the map')}</p>
        <Button
          variant="secondary"
          size="small"
          onClick={() => setIsLoadFailed(false)}
        >
          {t_i18n('Retry')}
        </Button>
      </div>
    );
  }

  return (
    <div
      key="map"
      ref={containerRef}
      aria-label="Map"
      style={{ width: '100%', height: '100%', minHeight: MIN_HEIGHT, borderRadius: 6, background: colors.water }}
    />
  );
};

export default GeoMapFallback;
