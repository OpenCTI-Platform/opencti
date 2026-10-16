import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getBase64ImageFromURL } from '../Image';
import { buildTimelinePdfDefinition, resolvePdfMakeEmbeddedImages, resolvePdfPageGeometry } from './htmlToPdf';

vi.mock('../Image', () => ({
  getBase64ImageFromURL: vi.fn(),
}));

const mockGetBase64ImageFromURL = vi.mocked(getBase64ImageFromURL);

describe('resolvePdfMakeEmbeddedImages', () => {
  const BASE_URL = 'https://example.com';

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('resolvePdfPageGeometry', () => {
    it('returns A4 portrait dimensions', () => {
      const result = resolvePdfPageGeometry('A4', 'portrait');
      expect(result.pageWidth).toBe(595.28);
      expect(result.pageHeight).toBe(841.89);
    });

    it('returns A3 landscape dimensions with swapped width/height', () => {
      const result = resolvePdfPageGeometry('A3', 'landscape');
      expect(result.pageWidth).toBe(1190.55);
      expect(result.pageHeight).toBe(841.89);
    });
  });

  it('returns an empty object when images is undefined', async () => {
    const result = await resolvePdfMakeEmbeddedImages(undefined, BASE_URL);
    expect(result).toEqual({});
    expect(mockGetBase64ImageFromURL).not.toHaveBeenCalled();
  });

  it('returns non-embedded images unchanged', async () => {
    const images = {
      logo: 'data:image/png;base64,abc123',
      banner: 'https://cdn.example.com/banner.png',
    };

    const result = await resolvePdfMakeEmbeddedImages(images, BASE_URL);

    expect(result).toEqual(images);
    expect(mockGetBase64ImageFromURL).not.toHaveBeenCalled();
  });

  it('keeps the data URI prefix when the resolved value already has one', async () => {
    mockGetBase64ImageFromURL.mockResolvedValue('data:image/png;base64,resolvedBase64');

    const result = await resolvePdfMakeEmbeddedImages({ chart: 'embedded/chart.png' }, BASE_URL);

    expect(result).toEqual({ chart: 'data:image/png;base64,resolvedBase64' });
  });

  it('prepends data:image/png;base64, when resolved value has no data URI prefix', async () => {
    mockGetBase64ImageFromURL.mockResolvedValue('rawBase64String==');

    const result = await resolvePdfMakeEmbeddedImages({ chart: 'embedded/chart.png' }, BASE_URL);

    expect(result).toEqual({ chart: 'data:image/png;base64,rawBase64String==' });
  });

  it('encodes special characters in the file name', async () => {
    mockGetBase64ImageFromURL.mockResolvedValue('data:image/png;base64,xyz');

    await resolvePdfMakeEmbeddedImages({ img: 'embedded/my file (1).png' }, BASE_URL);

    expect(mockGetBase64ImageFromURL).toHaveBeenCalledWith(
      'https://example.com/embedded/my%20file%20(1).png',
    );
  });

  it('handles a mix of embedded and non-embedded images', async () => {
    mockGetBase64ImageFromURL.mockResolvedValue('data:image/jpeg;base64,resolvedJpeg');

    const result = await resolvePdfMakeEmbeddedImages(
      { logo: 'data:image/png;base64,staticLogo', chart: 'embedded/chart.png' },
      BASE_URL,
    );

    expect(result).toEqual({
      logo: 'data:image/png;base64,staticLogo',
      chart: 'data:image/jpeg;base64,resolvedJpeg',
    });
    expect(mockGetBase64ImageFromURL).toHaveBeenCalledTimes(1);
  });

  it('does not mutate the original images object', async () => {
    mockGetBase64ImageFromURL.mockResolvedValue('data:image/png;base64,resolved');

    const images = { chart: 'embedded/chart.png' };
    const original = { ...images };

    await resolvePdfMakeEmbeddedImages(images, BASE_URL);

    expect(images).toEqual(original);
  });
});

describe('buildTimelinePdfDefinition', () => {
  // Same layout as the HTML export of the server: a drawing wider than any page, then the headline dates and the events
  const html = [
    '<div><h1>Timeline - Incident Demo</h1><p>Incident response - Generated at 2026-10-13 08:00 UTC</p>',
    '<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="900" viewBox="0 0 1200 900"><rect x="0" y="0" width="1200" height="900" fill="#ffffff"/></svg>',
    '<h2 class="pdf-pagebreak-before">Headline dates</h2><table><tbody><tr><td>Closure</td><td>Not reached</td></tr></tbody></table>',
    '<h2>Events</h2><table><thead><tr><th>Time</th><th>Title</th></tr></thead><tbody><tr><td>2026-03-01 00:00 UTC</td><td>Phishing</td></tr></tbody></table>',
    '</div>',
  ].join('');

  const findNodes = (node: unknown, match: (candidate: Record<string, unknown>) => boolean): Record<string, unknown>[] => {
    if (Array.isArray(node)) return node.flatMap((child) => findNodes(child, match));
    if (!node || typeof node !== 'object') return [];
    const record = node as Record<string, unknown>;
    return [...(match(record) ? [record] : []), ...Object.values(record).flatMap((value) => findNodes(value, match))];
  };

  it('lays the timeline out on an A4 landscape page, the drawing scaled to fit the first page whole', () => {
    const definition = buildTimelinePdfDefinition(html);
    expect(definition.pageSize).toBe('A4');
    expect(definition.pageOrientation).toBe('landscape');
    const { pageWidth, pageHeight } = resolvePdfPageGeometry('A4', 'landscape');
    const [margin] = definition.pageMargins as [number, number];
    const [drawing] = findNodes(definition.content, (node) => typeof node.svg === 'string');
    const [fitWidth, fitHeight] = drawing.fit as [number, number];
    expect(fitWidth).toBeCloseTo(pageWidth - 2 * margin);
    // Room is left above the drawing for the title of the export
    expect(fitHeight).toBeLessThan(pageHeight - 2 * margin - 40);
  });

  it('starts the headline dates and the events on the page after the drawing', () => {
    const definition = buildTimelinePdfDefinition(html);
    const pageBreakBefore = definition.pageBreakBefore as unknown as (node: unknown) => boolean;
    const ordered = findNodes(definition.content, (node) => typeof node.svg === 'string' || node.nodeName === 'H2');
    expect(ordered.map((node) => (typeof node.svg === 'string' ? 'drawing' : node.nodeName))).toEqual(['drawing', 'H2', 'H2']);
    expect(pageBreakBefore(ordered[1])).toBe(true);
    expect(pageBreakBefore(ordered[2])).toBe(false);
  });
});
