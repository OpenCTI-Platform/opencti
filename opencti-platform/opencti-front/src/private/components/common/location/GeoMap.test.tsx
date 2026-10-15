import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import GeoMap from './GeoMap';

const maplibreMock = vi.hoisted(() => ({ isWebGL2Supported: true }));

vi.mock('maplibre-gl', () => {
  class GPUInitializationError extends Error {}
  class Map {
    scrollZoom = { setWheelZoomRate: () => {} };

    constructor() {
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
});
