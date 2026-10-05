import { describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { fetchStreamInfo } from '../../../../src/database/stream/stream-handler';
import { laterStreamEventId, streamBoundaryOf, streamHighWaterMark } from '../../../../src/manager/sourceIntelligenceManager';

vi.mock('../../../../src/database/stream/stream-handler', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/database/stream/stream-handler')>();
  return { ...actual, fetchStreamInfo: vi.fn() };
});

const SCAN_START = 1759500000000;

describe('Source intelligence stream boundary of a full computation', () => {
  it('should resume the stream after the last event written before the scan, never after the scan time', async () => {
    vi.mocked(fetchStreamInfo).mockResolvedValue({
      lastEventId: `${SCAN_START}-3`,
      firstEventId: '1-0',
      firstEventDate: '',
      lastEventDate: '',
      streamSize: 4,
    });
    const boundary = await streamHighWaterMark(SCAN_START);
    expect(boundary).toBe(`${SCAN_START}-3`);
    // An event written during the scan in the same millisecond comes after the boundary: the stream still applies it
    expect(laterStreamEventId(boundary, `${SCAN_START}-4`)).toBe(`${SCAN_START}-4`);
    expect(laterStreamEventId(streamBoundaryOf(SCAN_START), `${SCAN_START}-4`)).toBe(streamBoundaryOf(SCAN_START));
  });

  it('should fall back to the end of the computation time when the stream cannot be read', async () => {
    vi.mocked(fetchStreamInfo).mockRejectedValue(new Error('empty stream'));
    expect(await streamHighWaterMark(SCAN_START)).toBe(streamBoundaryOf(SCAN_START));
  });
});
