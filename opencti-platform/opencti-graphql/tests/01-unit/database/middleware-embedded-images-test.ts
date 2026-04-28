import { describe, expect, it } from 'vitest';
import {
  collectTempImageTokensFromDescriptionFields,
  rewriteTempImageTokensInDescriptions,
} from '../../../src/database/middlewareEmbeddedImages';

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
