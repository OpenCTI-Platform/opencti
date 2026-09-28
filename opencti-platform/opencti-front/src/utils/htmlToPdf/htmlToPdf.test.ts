import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getBase64ImageFromURL } from '../Image';
import { resolvePdfMakeEmbeddedImages, resolvePdfPageGeometry } from './htmlToPdf';

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
