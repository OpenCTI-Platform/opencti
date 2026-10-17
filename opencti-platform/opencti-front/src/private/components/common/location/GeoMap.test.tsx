import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import GeoMap from './GeoMap';

const maplibreMock = vi.hoisted(() => ({ isWebGL2Supported: true, createdMaps: 0 }));

vi.mock('maplibre-gl', () => {
  class GPUInitializationError extends Error {}
  class Map {
    scrollZoom = { setWheelZoomRate: () => {} };

    constructor() {
      maplibreMock.createdMaps += 1;
      if (!maplibreMock.isWebGL2Supported) {
        throw new GPUInitializationError('WebGL2 is required to display this map.');
      }
    }

    on() {
      return this;
    }

    remove() {}
  }
  return { GPUInitializationError, Map, setWorkerUrl: () => {}, addProtocol: () => {} };
});
vi.mock('maplibre-gl/dist/maplibre-gl-worker.mjs?worker&url', () => ({ default: '' }));
vi.mock('pmtiles', () => ({
  Protocol: vi.fn(function Protocol() {
    return { tile: () => {} };
  }),
}));
vi.mock('./GeoMapFallback', () => ({
  default: () => <div>Fallback map</div>,
}));

describe('GeoMap', () => {
  beforeEach(() => {
    maplibreMock.isWebGL2Supported = true;
    maplibreMock.createdMaps = 0;
    localStorage.removeItem('opencti-map-renderer');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders the MapLibre map when WebGL2 is available', () => {
    const { getByText, queryByText } = testRender(<GeoMap title="Mini map" zoom={4} />);
    expect(getByText('Mini map')).toBeTruthy();
    expect(queryByText('Fallback map')).toBeNull();
  });

  it('renders the fallback map instead of crashing when WebGL2 is unavailable', async () => {
    maplibreMock.isWebGL2Supported = false;
    const { getByText, findByText } = testRender(<GeoMap title="Mini map" zoom={4} />);
    expect(getByText('Mini map')).toBeTruthy();
    expect(await findByText('Fallback map')).toBeTruthy();
  });

  it('renders the fallback map without creating a MapLibre map when forced from local storage', async () => {
    localStorage.setItem('opencti-map-renderer', 'fallback');
    const { findByText } = testRender(<GeoMap title="Mini map" zoom={4} />);
    expect(await findByText('Fallback map')).toBeTruthy();
    expect(maplibreMock.createdMaps).toBe(0);
  });

  it('renders the MapLibre map when local storage cannot be accessed', () => {
    vi.spyOn(window, 'localStorage', 'get').mockImplementation(() => {
      throw new DOMException('The operation is insecure.', 'SecurityError');
    });
    const { getByText, queryByText } = testRender(<GeoMap title="Mini map" zoom={4} />);
    expect(getByText('Mini map')).toBeTruthy();
    expect(queryByText('Fallback map')).toBeNull();
    expect(maplibreMock.createdMaps).toBe(1);
  });
});
