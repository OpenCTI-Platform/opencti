import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  collectTempImageTokensFromDescriptionFields,
  resolveEmbeddedImagesInDescriptionFieldsForExport,
  rewriteEmbeddedDataUriImagesInDescriptions,
  rewriteEmbeddedDataUriImagesInUpdateInputs,
  rewriteMarkdownPatchUpdatesForExport,
  rewriteTempImageTokensInDescriptions,
} from '../../../src/database/middlewareEmbeddedImages';
import { uploadToStorage } from '../../../src/database/file-storage';
import { getFileContent } from '../../../src/database/raw-file-storage';
import { getDraftContext } from '../../../src/utils/draftContext';
import { getDraftFilePrefix } from '../../../src/database/draft-utils';

vi.mock('../../../src/database/file-storage', () => ({
  uploadToStorage: vi.fn(),
}));

vi.mock('../../../src/database/raw-file-storage', () => ({
  getFileContent: vi.fn(),
}));

vi.mock('../../../src/utils/draftContext', () => ({
  getDraftContext: vi.fn(),
}));

vi.mock('../../../src/database/draft-utils', () => ({
  getDraftFilePrefix: vi.fn(),
}));

describe('middlewareEmbeddedImages temp-token helpers', () => {
  it('should collect temp image UUID tokens in markdown order across nested description fields', () => {
    const payload = {
      description: [
        '![a](opencti-image://temp/11111111-1111-1111-1111-111111111111)',
        '![b](/storage/temp/22222222-2222-2222-2222-222222222222)',
      ].join('\n'),
      nested: {
        content: '![c](https://platform.local/temp/33333333-3333-3333-3333-333333333333)',
      },
    };

    const tokens = collectTempImageTokensFromDescriptionFields(payload);

    expect(tokens).toEqual([
      '11111111-1111-1111-1111-111111111111',
      '22222222-2222-2222-2222-222222222222',
      '33333333-3333-3333-3333-333333333333',
    ]);
  });

  it('should rewrite only mapped temp image tokens and keep other markdown image links unchanged', () => {
    const payload: Record<string, unknown> = {
      description: [
        '![mapped](opencti-image://temp/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa)',
        '![unmapped](opencti-image://temp/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb)',
        '![regular](https://example.org/static.png)',
      ].join('\n'),
      nested: {
        x_opencti_description: '![mapped2](/storage/temp/cccccccc-cccc-cccc-cccc-cccccccccccc)',
      },
    };

    const tokenToUrl = new Map<string, string>([
      ['aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '/storage/view/embedded/Report/r-1/a.png'],
      ['cccccccc-cccc-cccc-cccc-cccccccccccc', '/storage/view/embedded/Report/r-1/c.png'],
    ]);

    rewriteTempImageTokensInDescriptions(payload, tokenToUrl);

    expect(payload.description).toContain('![mapped](/storage/view/embedded/Report/r-1/a.png)');
    expect(payload.description).toContain('![unmapped](opencti-image://temp/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb)');
    expect(payload.description).toContain('![regular](https://example.org/static.png)');

    expect((payload.nested as Record<string, unknown>).x_opencti_description)
      .toContain('![mapped2](/storage/view/embedded/Report/r-1/c.png)');
  });
});

describe('middlewareEmbeddedImages markdown rewrite helpers', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(getDraftContext).mockReturnValue(undefined);
    vi.mocked(getDraftFilePrefix).mockReturnValue('draft/d-1/');
  });

  it('should rewrite data URI images in description fields for create-like payloads', async () => {
    vi.mocked(uploadToStorage).mockResolvedValue({
      upload: { name: 'Report/r-1/image-a.png' },
    } as any);

    const payload: Record<string, unknown> = {
      description: `![a](data:image/png;base64,${Buffer.from('img-a').toString('base64')})`,
    };

    await rewriteEmbeddedDataUriImagesInDescriptions(
      {} as any,
      {} as any,
      payload,
      {
        entityType: 'Report',
        entityId: 'r-1',
        entity: { internal_id: 'r-1', entity_type: 'Report' } as any,
        fileMarkings: [],
      },
    );

    expect(payload.description).toContain('![a](embedded/Report/r-1/image-a.png)');
    expect(uploadToStorage).toHaveBeenCalledTimes(1);
  });

  it('should rewrite data URI images in update inputs for upsert/update-like patches', async () => {
    vi.mocked(uploadToStorage).mockResolvedValue({
      upload: { name: 'Report/r-2/image-b.png' },
    } as any);

    const updates = [
      {
        key: 'description',
        value: [`![b](data:image/png;base64,${Buffer.from('img-b').toString('base64')})`],
        operation: 'replace',
      },
      {
        key: 'name',
        value: ['untouched'],
        operation: 'replace',
      },
    ] as any[];

    await rewriteEmbeddedDataUriImagesInUpdateInputs(
      {} as any,
      {} as any,
      updates as any,
      {
        entityType: 'Report',
        entityId: 'r-2',
        entity: { internal_id: 'r-2', entity_type: 'Report' } as any,
        fileMarkings: [],
      },
    );

    expect(updates[0].value[0]).toContain('![b](embedded/Report/r-2/image-b.png)');
    expect(updates[1].value[0]).toBe('untouched');
  });

  it('should resolve embedded markdown image URLs to data URIs for export without mutating input', async () => {
    vi.mocked(getFileContent).mockResolvedValue('Zm9v' as any);

    const payload = {
      description: '![x](embedded/Report/r-3/image-c.png)',
      name: 'Report name',
    };

    const rewritten = await resolveEmbeddedImagesInDescriptionFieldsForExport(
      {} as any,
      payload,
      { entityType: 'Report', entityId: 'r-3' },
    );

    expect(rewritten.description).toContain('data:image/png;base64,Zm9v');
    expect(payload.description).toBe('![x](embedded/Report/r-3/image-c.png)');
    expect(rewritten.name).toBe('Report name');
  });

  it('should rewrite markdown patch updates for export and keep non-string values untouched', async () => {
    vi.mocked(getFileContent).mockResolvedValue('YmFy' as any);

    const updates = [
      {
        key: 'description',
        value: ['![x](embedded/Report/r-4/image-d.png)', { keep: true }],
        operation: 'replace',
      },
      {
        key: 'name',
        value: ['not-markdown-field'],
        operation: 'replace',
      },
    ] as any[];

    const rewritten = await rewriteMarkdownPatchUpdatesForExport(
      {} as any,
      updates as any,
      { entityType: 'Report', entityId: 'r-4' },
    );

    expect(rewritten[0].value[0]).toContain('data:image/png;base64,YmFy');
    expect(rewritten[0].value[1]).toEqual({ keep: true });
    expect(rewritten[1].value[0]).toBe('not-markdown-field');
  });
});
