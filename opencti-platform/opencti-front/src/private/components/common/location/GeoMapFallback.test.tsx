import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { waitFor } from '@testing-library/react';
import type { Position } from 'geojson';
import testRender from '../../../../utils/tests/test-render';
import GeoMapFallback from './GeoMapFallback';
import { loadCountries, type CountriesCollection } from './countries';

vi.hoisted(() => {
  SVGSVGElement.prototype.createSVGRect = () => ({ x: 0, y: 0, width: 0, height: 0 }) as DOMRect;
});

vi.mock('./countries', () => ({ loadCountries: vi.fn() }));

const square = (west: number, south: number, size: number): Position[] => [
  [west, south],
  [west + size, south],
  [west + size, south + size],
  [west, south + size],
  [west, south],
];

const countriesFile = (): CountriesCollection => ({
  type: 'FeatureCollection',
  features: [
    {
      type: 'Feature',
      properties: { ISO2: 'FR', ISO3: 'FRA', NAME: 'France', LON: 2.5, LAT: 47.5 },
      geometry: { type: 'Polygon', coordinates: [square(0, 45, 5)] },
    },
    {
      type: 'Feature',
      properties: { ISO2: 'DE', ISO3: 'DEU', NAME: 'Germany', LON: 7.5, LAT: 47.5 },
      geometry: { type: 'Polygon', coordinates: [square(5, 45, 5)] },
    },
  ],
});

const HIGHLIGHT = '#ff0000';

class TrackingResizeObserver {
  static instances: TrackingResizeObserver[] = [];

  element: Element | null = null;

  disconnect = vi.fn();

  constructor() {
    TrackingResizeObserver.instances.push(this);
  }

  observe(element: Element) {
    this.element = element;
  }

  unobserve() {}
}

const leafletIdOf = (element: Element | null) => (element as (Element & { _leaflet_id?: number }) | null)?._leaflet_id;

describe('GeoMapFallback', () => {
  beforeEach(() => {
    TrackingResizeObserver.instances = [];
    vi.stubGlobal('ResizeObserver', TrackingResizeObserver);
    vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockReturnValue(400);
    vi.spyOn(HTMLElement.prototype, 'clientHeight', 'get').mockReturnValue(300);
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null);
    vi.mocked(loadCountries).mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('draws highlighted countries, markers and country names', async () => {
    vi.mocked(loadCountries).mockResolvedValue(countriesFile());
    const { container, findByText } = testRender(
      <GeoMapFallback
        zoom={4}
        countries={[{ x_opencti_aliases: ['FRA'], color: HIGHLIGHT }]}
        markers={[{ position: { latitude: 52.5, longitude: 8 }, iconUrl: 'city.png' }]}
      />,
    );
    await waitFor(() => expect(container.querySelector(`path[fill="${HIGHLIGHT}"]`)).not.toBeNull());
    expect(container.querySelector('img.leaflet-marker-icon[src="city.png"]')).not.toBeNull();
    expect(await findByText('France')).toBeTruthy();
    expect(await findByText('Germany')).toBeTruthy();
  });

  it('shows an error when the countries cannot be loaded and draws the map on retry', async () => {
    vi.mocked(loadCountries)
      .mockRejectedValueOnce(new Error('Unable to load country boundaries (503)'))
      .mockResolvedValueOnce(countriesFile());
    const { container, findByText, queryByText, getByRole, user } = testRender(
      <GeoMapFallback zoom={4} countries={[{ x_opencti_aliases: ['FRA'], color: HIGHLIGHT }]} />,
    );
    expect(await findByText('Failed to load the map')).toBeTruthy();
    await user.click(getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(container.querySelector(`path[fill="${HIGHLIGHT}"]`)).not.toBeNull());
    expect(queryByText('Failed to load the map')).toBeNull();
    expect(loadCountries).toHaveBeenCalledTimes(2);
  });

  it('releases the map and its resize observer when loading fails', async () => {
    vi.mocked(loadCountries).mockRejectedValue(new Error('Unable to load country boundaries (503)'));
    const { findByText } = testRender(<GeoMapFallback zoom={4} />);
    await findByText('Failed to load the map');
    const [observer] = TrackingResizeObserver.instances;
    expect(observer.disconnect).toHaveBeenCalled();
    expect(leafletIdOf(observer.element)).toBeUndefined();
  });

  it('releases the map and its resize observer on unmount', async () => {
    vi.mocked(loadCountries).mockResolvedValue(countriesFile());
    const { container, unmount } = testRender(<GeoMapFallback zoom={4} />);
    await waitFor(() => expect(container.querySelector('path')).not.toBeNull());
    const [observer] = TrackingResizeObserver.instances;
    expect(leafletIdOf(observer.element)).toBeDefined();
    unmount();
    expect(observer.disconnect).toHaveBeenCalled();
    expect(leafletIdOf(observer.element)).toBeUndefined();
  });
});
