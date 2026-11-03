import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import GeoMap from './GeoMap';

const WEBGL_UNAVAILABLE_MESSAGE = 'This map cannot be displayed because your browser does not support WebGL2 or has it disabled.';

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

describe('GeoMap', () => {
  beforeEach(() => {
    maplibreMock.isWebGL2Supported = true;
  });

  it('renders the map when WebGL2 is available', () => {
    const { getByText, queryByText } = testRender(<GeoMap title="Mini map" zoom={4} />);
    expect(getByText('Mini map')).toBeTruthy();
    expect(queryByText(WEBGL_UNAVAILABLE_MESSAGE)).toBeNull();
  });

  it('renders a placeholder instead of crashing when WebGL2 is unavailable', () => {
    maplibreMock.isWebGL2Supported = false;
    const { getByText } = testRender(<GeoMap title="Mini map" zoom={4} />);
    expect(getByText('Mini map')).toBeTruthy();
    expect(getByText(WEBGL_UNAVAILABLE_MESSAGE)).toBeTruthy();
  });
});
