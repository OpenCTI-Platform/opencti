import { beforeEach, describe, expect, it, vi } from 'vitest';
import { buildCreateEvent, buildStixUpdateEvent } from '../../../src/database/stream/stream-utils';
import { convertStoreToStix_2_1 } from '../../../src/database/stix-2-1-converter';
import { getFileContent } from '../../../src/database/raw-file-storage';
import { getDraftContext } from '../../../src/utils/draftContext';

vi.mock('../../../src/database/stix-2-1-converter', () => ({
  convertStoreToStix_2_1: vi.fn(),
}));

vi.mock('../../../src/database/raw-file-storage', () => ({
  getFileContent: vi.fn(),
}));

vi.mock('../../../src/utils/draftContext', () => ({
  getDraftContext: vi.fn(),
}));

const buildStix = (description: string) => ({
  id: 'report--1',
  type: 'report',
  description,
  extensions: {
    'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
      type: 'Report',
      id: 'report-internal-1',
    },
  },
});

describe('stream event embedded image resolution (produce side)', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(getDraftContext).mockReturnValue(undefined);
    vi.mocked(getFileContent).mockResolvedValue('Zm9v' as any);
  });

  it('inlines embedded markdown images as base64 data URIs in create events', async () => {
    vi.mocked(convertStoreToStix_2_1).mockReturnValue(
      buildStix('![x](embedded/Report/report-internal-1/image.png)') as any,
    );

    const event = await buildCreateEvent({} as any, { origin: {} } as any, { entity_type: 'Report' } as any, '-');

    expect((event.data as any).description).toContain('data:image/png;base64,Zm9v');
    expect((event.data as any).description).not.toContain('embedded/Report');
    expect(getFileContent).toHaveBeenCalledWith('embedded/Report/report-internal-1/image.png', 'base64');
  });

  it('inlines embedded markdown images as base64 data URIs in update events', async () => {
    const previousStix = buildStix('no image here');
    const currentStix = buildStix('![x](embedded/Report/report-internal-1/image.png)');

    const event = await buildStixUpdateEvent(
      {} as any,
      { origin: {} } as any,
      previousStix as any,
      currentStix as any,
      [{ type: 'update', key: 'description' } as any],
    );

    expect((event.data as any).description).toContain('data:image/png;base64,Zm9v');
    // the patch produced for consumers should carry the resolved base64, not the storage path
    const descriptionPatch = event.context.patch.find((op: any) => op.path === '/description');
    expect(descriptionPatch).toBeDefined();
    expect((descriptionPatch as any).value).toContain('data:image/png;base64,Zm9v');
  });

  it('leaves descriptions without embedded images untouched (no file fetch)', async () => {
    vi.mocked(convertStoreToStix_2_1).mockReturnValue(buildStix('plain description') as any);

    const event = await buildCreateEvent({} as any, { origin: {} } as any, { entity_type: 'Report' } as any, '-');

    expect((event.data as any).description).toBe('plain description');
    expect(getFileContent).not.toHaveBeenCalled();
  });
});
