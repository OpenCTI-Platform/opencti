import { Readable } from 'node:stream';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  fullEntitiesList: vi.fn(),
  storeLoadById: vi.fn(),
}));
vi.mock('../../../../src/modules/fintelDesign/fintelDesign-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/fintelDesign/fintelDesign-domain')>()),
  addFintelDesign: vi.fn(),
  fintelDesignEditField: vi.fn(),
  fintelDesignDelete: vi.fn(),
}));
vi.mock('../../../../src/modules/fintelDesign/fintelDesign-logo', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/fintelDesign/fintelDesign-logo')>()),
  readFintelDesignLogo: vi.fn(),
}));

import { fullEntitiesList, storeLoadById } from '../../../../src/database/middleware-loader';
import { addFintelDesign, fintelDesignDelete, fintelDesignEditField } from '../../../../src/modules/fintelDesign/fintelDesign-domain';
import {
  FINTEL_DESIGN_LOGO_MAX_SIZE,
  fintelDesignLogoExtension,
  isCompleteFintelDesignLogo,
  limitFintelDesignLogoStream,
  readFintelDesignLogo,
  readFintelDesignLogoUpload,
} from '../../../../src/modules/fintelDesign/fintelDesign-logo';
import { exportFintelDesign } from '../../../../src/modules/fintelDesign/fintelDesign-export';
import { importFintelDesign } from '../../../../src/modules/fintelDesign/fintelDesign-import';
import { FINTEL_DESIGN_NAME_MAX_LENGTH, fintelDesignImportSchema } from '../../../../src/modules/fintelDesign/fintelDesign-import-schema';
import type { BasicStoreEntityFintelDesign } from '../../../../src/modules/fintelDesign/fintelDesign-types';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { defaultFintelDesign, nightFintelDesign, PNG_LOGO } from '../configPreset/configPreset-fintelDesigns-fixtures';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const configuration = exportFintelDesign(defaultFintelDesign);
const logoOf = (content: Buffer | null) => ({ read: vi.fn().mockResolvedValue(content) });
const overwrite = { mode: ConfigImportMode.Overwrite };
const copy = { mode: ConfigImportMode.Copy };

const withExisting = (design?: BasicStoreEntityFintelDesign) => vi.mocked(storeLoadById).mockResolvedValue(design as never);
const withDesignsNamed = (...designs: BasicStoreEntityFintelDesign[]) => vi.mocked(fullEntitiesList).mockImplementation(async (_ctx, _user, _types, args) => {
  const name = (args as { filters: { filters: { values: string[] }[] } }).filters.filters[0].values[0];
  return designs.filter((design) => design.name === name) as never;
});
const readUpload = async (upload: unknown) => {
  const { createReadStream, filename } = await (upload as Promise<{ createReadStream: () => Readable; filename: string }>);
  const chunks: Buffer[] = [];
  for await (const chunk of createReadStream()) {
    chunks.push(chunk as Buffer);
  }
  return { content: Buffer.concat(chunks), filename };
};

beforeEach(() => {
  vi.resetAllMocks();
  withExisting();
  withDesignsNamed();
  vi.mocked(addFintelDesign).mockResolvedValue({ id: 'new-design-id' } as never);
  vi.mocked(readFintelDesignLogo).mockResolvedValue(PNG_LOGO);
});

describe('Fintel design export and import schema', () => {
  it('exports the import format only, and the import takes it back as is', () => {
    expect(configuration).toEqual({
      standard_id: defaultFintelDesign.standard_id,
      name: 'Filigran report',
      description: 'The design of the reports',
      gradiantFromColor: '#00020c',
      gradiantToColor: '#001bda',
      textColor: '#ffffff',
      default: true,
    });
    expect(fintelDesignImportSchema.parse(configuration)).toEqual(configuration);
    expect(fintelDesignImportSchema.parse(exportFintelDesign(nightFintelDesign))).toEqual(exportFintelDesign(nightFintelDesign));
  });

  it('refuses unknown keys, another standard id, a gradient color that is not hex and a blank name', () => {
    expect(fintelDesignImportSchema.safeParse({ ...configuration, file_id: 'fintelDesigns/x' }).success).toBe(false);
    expect(fintelDesignImportSchema.safeParse({ ...configuration, standard_id: 'theme--2c5e8f1a-4b3d-5e6f-8a9b-0c1d2e3f4a5b' }).success).toBe(false);
    expect(fintelDesignImportSchema.safeParse({ ...configuration, gradiantFromColor: 'red' }).success).toBe(false);
    expect(fintelDesignImportSchema.safeParse({ ...configuration, gradiantToColor: 'rgb(0,0,0)' }).success).toBe(false);
    expect(fintelDesignImportSchema.safeParse({ ...configuration, name: '  ' }).success).toBe(false);
    expect(fintelDesignImportSchema.safeParse({ ...configuration, gradiantFromColor: null, textColor: '' }).success).toBe(true);
  });

  it('takes back any text color the form stores, so that every design exported is imported back', async () => {
    ['black', 'rgb(0,0,0)', '#000'].forEach((textColor) => {
      expect(fintelDesignImportSchema.safeParse({ ...configuration, textColor }).success).toBe(true);
    });
    expect(await importFintelDesign(context, user, { ...configuration, textColor: 'black' }, undefined, overwrite)).toMatchObject({ status: 'created' });
    expect(addFintelDesign).toHaveBeenCalledWith(context, user, expect.objectContaining({ textColor: 'black', default: true }));
  });
});

describe('Fintel design logo format', () => {
  it('recognizes the image formats from their bytes, an SVG after its prolog, and nothing else', async () => {
    expect(await fintelDesignLogoExtension(PNG_LOGO)).toBe('png');
    expect(await fintelDesignLogoExtension(Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00]))).toBe('jpg');
    expect(await fintelDesignLogoExtension(Buffer.from('GIF89a....'))).toBe('gif');
    expect(await fintelDesignLogoExtension(Buffer.from('RIFF\u0000\u0000\u0000\u0000WEBPVP8 '))).toBe('webp');
    expect(await fintelDesignLogoExtension(Buffer.from('﻿<?xml version="1.0"?>\n<!-- logo -->\n<svg xmlns="http://www.w3.org/2000/svg"></svg>'))).toBe('svg');
    expect(await fintelDesignLogoExtension(Buffer.from('<html><body>svg</body></html>'))).toBeUndefined();
    expect(await fintelDesignLogoExtension(Buffer.from('not an image'))).toBeUndefined();
  });

  it('recognizes an SVG by its root element, whatever comes before it, and not a document that merely holds an svg element', async () => {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg"><svg x="1"></svg></svg>';
    // A leading comment longer than any fixed window, a self-closed root, and the doctype with an internal subset of the vector editors
    expect(await fintelDesignLogoExtension(Buffer.from(`<!--${'x'.repeat(10000)}-->\n${svg}`))).toBe('svg');
    expect(await fintelDesignLogoExtension(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>'))).toBe('svg');
    const doctype = '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" [<!ENTITY ns ">]">]>';
    expect(await fintelDesignLogoExtension(Buffer.from(`<?xml version="1.0"?>${doctype}\n${svg}`))).toBe('svg');
    // An apostrophe in a comment of the internal subset is text, not a quote
    expect(await fintelDesignLogoExtension(Buffer.from(`<!DOCTYPE svg [<!-- the logo's entities --><!ENTITY ns "x">]>${svg}`))).toBe('svg');
    // Another root: an HTML page with an inline svg, a commented-out svg, an element whose name starts with svg
    expect(await fintelDesignLogoExtension(Buffer.from(`<!DOCTYPE html><html><body>${svg}</body></html>`))).toBeUndefined();
    expect(await fintelDesignLogoExtension(Buffer.from(`<!-- ${svg} --><html></html>`))).toBeUndefined();
    expect(await fintelDesignLogoExtension(Buffer.from('<svgfoo></svgfoo>'))).toBeUndefined();
    // Text before the first markup: not an XML document
    expect(await fintelDesignLogoExtension(Buffer.from(`logo ${svg}`))).toBeUndefined();
    // A prolog never closed, or nothing after it
    expect(await fintelDesignLogoExtension(Buffer.from(`<!-- ${svg}`))).toBeUndefined();
    expect(await fintelDesignLogoExtension(Buffer.from('<?xml version="1.0"?>\n'))).toBeUndefined();
  });
});

describe('Fintel design logo completeness', () => {
  it('accepts a logo that goes on to the end of its format, data after it included, and refuses one cut short', async () => {
    const jpg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0xff, 0xd9]);
    const gif = Buffer.concat([Buffer.from('GIF89a'), Buffer.alloc(13), Buffer.from([0x3b])]);
    const webp = Buffer.concat([Buffer.from('RIFF'), Buffer.from([12, 0, 0, 0]), Buffer.from('WEBPVP8 ....')]);
    const complete: [Buffer, string][] = [
      [PNG_LOGO, 'png'], [Buffer.concat([PNG_LOGO, Buffer.from('trailing')]), 'png'],
      [jpg, 'jpg'], [Buffer.concat([jpg, Buffer.from([0x00])]), 'jpg'],
      [gif, 'gif'], [Buffer.concat([gif, Buffer.from('\r\n\u0000')]), 'gif'],
      [webp, 'webp'],
      [Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/></svg>\n'), 'svg'], [Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>'), 'svg'],
    ];
    for (const [content, extension] of complete) {
      expect(await fintelDesignLogoExtension(content)).toBe(extension);
      expect(isCompleteFintelDesignLogo(content, extension)).toBe(true);
    }
    // The signature alone, or a logo whose end is missing
    const truncated: [Buffer, string][] = [
      [PNG_LOGO.subarray(0, 8), 'png'], [PNG_LOGO.subarray(0, PNG_LOGO.length - 4), 'png'],
      [Buffer.from([0xff, 0xd8, 0xff]), 'jpg'], [jpg.subarray(0, jpg.length - 1), 'jpg'],
      [Buffer.from('GIF89a'), 'gif'], [gif.subarray(0, gif.length - 1), 'gif'],
      // A trailer byte in the image data does not end it: what follows is not padding
      [Buffer.concat([gif.subarray(0, gif.length - 1), Buffer.from([0x3b, 0x01, 0x02])]), 'gif'],
      [webp.subarray(0, webp.length - 1), 'webp'],
      [Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/>'), 'svg'],
    ];
    for (const [content, extension] of truncated) {
      // Too short to be recognized at all (a PNG signature alone), or recognized and incomplete: refused either way
      const recognized = await fintelDesignLogoExtension(content);
      expect(recognized === undefined || recognized === extension).toBe(true);
      expect(isCompleteFintelDesignLogo(content, extension)).toBe(false);
    }
  });

  it('finds the end of an SVG root outside its quoted values, its comments and its CDATA sections', () => {
    const isCompleteSvg = (text: string) => isCompleteFintelDesignLogo(Buffer.from(text), 'svg');
    // Closed on itself, a '>' or '/>' in a quoted value, the closing tag after a comment or a CDATA section, an XML declaration first
    expect(isCompleteSvg('<svg width="1"\n/>')).toBe(true);
    expect(isCompleteSvg('<svg a="x>y" b=\'/>\'><path/></svg>')).toBe(true);
    expect(isCompleteSvg('<svg><!-- a --><![CDATA[ b ]]></svg >')).toBe(true);
    expect(isCompleteSvg('\uFEFF<?xml version="1.0"?><svg></svg>')).toBe(true);
    // A '/>' or a closing tag that is only text: in a quoted value, in a comment, in a CDATA section; a start tag never closed
    expect(isCompleteSvg('<svg a="/>"')).toBe(false);
    expect(isCompleteSvg('<svg a="/>">')).toBe(false);
    expect(isCompleteSvg('<svg><path/><!-- </svg> -->')).toBe(false);
    expect(isCompleteSvg('<svg><![CDATA[ </svg> ]]>')).toBe(false);
    expect(isCompleteSvg('<svg><!-- </svg>')).toBe(false);
    expect(isCompleteSvg('<svg><svgfoo/></svgfoo>')).toBe(false);
  });

  it('checks an SVG in a time linear in its length, whatever it holds', async () => {
    // A root start tag never closed, followed by more starts of svg tags: a backtracking search would rescan the rest from each of them
    const unclosed = Buffer.from(`<svg ${'<svg'.repeat(50_000)}`);
    const unclosedComments = Buffer.from(`<svg>${'<!--'.repeat(50_000)}`);
    const start = performance.now();
    expect(await fintelDesignLogoExtension(unclosed)).toBe('svg');
    expect(isCompleteFintelDesignLogo(unclosed, 'svg')).toBe(false);
    expect(isCompleteFintelDesignLogo(unclosedComments, 'svg')).toBe(false);
    // About 200 KB each: seconds with a quadratic scan, milliseconds with a linear one. The bound leaves room for a slow CI machine
    expect(performance.now() - start).toBeLessThan(500);
  });

  it('refuses at the import a logo cut short, whatever the mode, and writes nothing', async () => {
    const truncated = logoOf(Buffer.from([0xff, 0xd8, 0xff]));
    expect(await importFintelDesign(context, user, configuration, truncated, overwrite)).toMatchObject({ status: 'failed', code: 'logo_invalid' });
    expect(await importFintelDesign(context, user, configuration, truncated, copy)).toMatchObject({ status: 'failed', code: 'logo_invalid' });
    expect(addFintelDesign).not.toHaveBeenCalled();
    expect(fintelDesignEditField).not.toHaveBeenCalled();
  });
});

describe('Fintel design logo upload', () => {
  const read = async (source: Readable) => {
    const chunks: Buffer[] = [];
    for await (const chunk of limitFintelDesignLogoStream(source)) {
      chunks.push(chunk as Buffer);
    }
    return Buffer.concat(chunks);
  };

  it('lets a logo up to the limit through as it is, and refuses a larger one as soon as it goes over, destroying the upload', async () => {
    const atLimit = Buffer.alloc(FINTEL_DESIGN_LOGO_MAX_SIZE, 1);
    expect((await read(Readable.from([atLimit.subarray(0, 1024), atLimit.subarray(1024)]))).equals(atLimit)).toBe(true);

    const upload = Readable.from([atLimit, Buffer.from([1]), Buffer.from('never read')]);
    await expect(read(upload)).rejects.toThrow('The logo of the fintel design is too large');
    expect(upload.destroyed).toBe(true);
  });

  it('stores only a logo the import of a bundle takes back: recognized from its bytes, complete, within the limit', async () => {
    expect((await readFintelDesignLogoUpload(Readable.from([PNG_LOGO.subarray(0, 10), PNG_LOGO.subarray(10)]))).equals(PNG_LOGO)).toBe(true);
    // Named as an image by its file name, but not one: another content, a logo cut short
    await expect(readFintelDesignLogoUpload(Readable.from([Buffer.from('<html></html>')]))).rejects.toThrow('The logo of the fintel design is not a supported image');
    await expect(readFintelDesignLogoUpload(Readable.from([Buffer.from([0xff, 0xd8, 0xff])]))).rejects.toThrow('The logo of the fintel design is not a supported image');
    await expect(readFintelDesignLogoUpload(Readable.from([PNG_LOGO.subarray(0, 20)]))).rejects.toThrow('The logo of the fintel design is not a supported image');
    await expect(readFintelDesignLogoUpload(Readable.from([Buffer.alloc(FINTEL_DESIGN_LOGO_MAX_SIZE + 1)]))).rejects.toThrow('The logo of the fintel design is too large');
  });
});

describe('Fintel design import', () => {
  it('refuses an invalid configuration without reading the platform', async () => {
    const result = await importFintelDesign(context, user, { name: 'No id' }, undefined, overwrite);
    expect(result).toMatchObject({ status: 'failed', code: 'invalid', exists: false });
    expect(storeLoadById).not.toHaveBeenCalled();
  });

  it('creates a design that does not exist under its standard id, stores its logo then makes it the default, and writes nothing on a dry run', async () => {
    const logo = logoOf(PNG_LOGO);
    expect(await importFintelDesign(context, user, configuration, logo, { ...overwrite, dryRun: true })).toMatchObject({ status: 'created', exists: false });
    expect(addFintelDesign).not.toHaveBeenCalled();
    expect(fintelDesignEditField).not.toHaveBeenCalled();

    expect(await importFintelDesign(context, user, configuration, logo, overwrite)).toMatchObject({ status: 'created', exists: false });
    expect(storeLoadById).toHaveBeenCalledWith(context, user, defaultFintelDesign.standard_id, 'FintelDesign');
    expect(logo.read).toHaveBeenCalledWith(FINTEL_DESIGN_LOGO_MAX_SIZE);
    expect(addFintelDesign).toHaveBeenCalledWith(context, user, {
      name: 'Filigran report',
      description: 'The design of the reports',
      gradiantFromColor: '#00020c',
      gradiantToColor: '#001bda',
      textColor: '#ffffff',
      // The default once the logo is stored, by the same edit
      default: false,
      standard_id: defaultFintelDesign.standard_id,
    });
    const [[, , { id, file, input }]] = vi.mocked(fintelDesignEditField).mock.calls;
    expect([id, input]).toEqual(['new-design-id', [{ key: 'default', value: [true] }]]);
    // The domain checks that the file is an image from its extension: the one of the bytes
    expect(await readUpload(file)).toEqual({ content: PNG_LOGO, filename: 'logo.png' });
  });

  it('creates a design without logo when the bundle has none, and not as the default when it is not', async () => {
    expect(await importFintelDesign(context, user, exportFintelDesign(nightFintelDesign), undefined, overwrite)).toMatchObject({ status: 'created' });
    expect(addFintelDesign).toHaveBeenCalledWith(context, user, expect.objectContaining({ name: 'Night briefing', default: false, textColor: undefined, description: undefined }));
    expect(fintelDesignEditField).not.toHaveBeenCalled();
    // Without logo, the default design is created as the default at once
    await importFintelDesign(context, user, configuration, undefined, overwrite);
    expect(vi.mocked(addFintelDesign).mock.calls[1][2]).toMatchObject({ default: true });
    expect(fintelDesignEditField).not.toHaveBeenCalled();

    // A logo that cannot be stored: the design created is deleted, the item fails, the default is never moved
    vi.mocked(fintelDesignEditField).mockRejectedValueOnce(new Error('storage down'));
    await expect(importFintelDesign(context, user, configuration, logoOf(PNG_LOGO), overwrite)).rejects.toThrow('storage down');
    expect(vi.mocked(addFintelDesign).mock.calls[2][2]).toMatchObject({ default: false });
    expect(fintelDesignDelete).toHaveBeenCalledWith(context, user, 'new-design-id');
    expect(fintelDesignEditField).toHaveBeenCalledTimes(1);
    // A deletion that fails too does not hide the error of the logo
    vi.mocked(fintelDesignEditField).mockRejectedValueOnce(new Error('storage down'));
    vi.mocked(fintelDesignDelete).mockRejectedValueOnce(new Error('delete failed'));
    await expect(importFintelDesign(context, user, configuration, logoOf(PNG_LOGO), copy)).rejects.toThrow('storage down');
  });

  it('reads the previous default before creating anything: a read that fails leaves no design behind', async () => {
    vi.mocked(fullEntitiesList).mockRejectedValue(new Error('search timeout'));
    await expect(importFintelDesign(context, user, configuration, logoOf(PNG_LOGO), overwrite)).rejects.toThrow('search timeout');
    expect(addFintelDesign).not.toHaveBeenCalled();
    expect(fintelDesignEditField).not.toHaveBeenCalled();
    // Not read when it is not needed: a design that is not the default of the bundle, or the default without a logo
    vi.mocked(fullEntitiesList).mockResolvedValue([]);
    await importFintelDesign(context, user, { ...configuration, default: false }, logoOf(PNG_LOGO), overwrite);
    await importFintelDesign(context, user, configuration, undefined, overwrite);
    expect(vi.mocked(fullEntitiesList).mock.calls.filter(([, , , args]) => JSON.stringify(args).includes('"default"'))).toHaveLength(1);
  });

  it('gives the default back to the previous design before deleting a design the failed edit had already made the default', async () => {
    const previousDefault = { ...nightFintelDesign, id: 'previous-default-id', default: true } as BasicStoreEntityFintelDesign;
    vi.mocked(fullEntitiesList).mockImplementation(async (_ctx, _user, _types, args) => {
      const [filter] = (args as { filters: { filters: { key: string[] }[] } }).filters.filters;
      return (filter.key[0] === 'default' ? [previousDefault] : []) as never;
    });
    // The edit made the design the default (and took the default away from the previous one), then its event failed
    vi.mocked(storeLoadById).mockImplementation(async (_ctx, _user, id) => (id === 'new-design-id' ? { id, default: true } : undefined) as never);
    vi.mocked(fintelDesignEditField).mockRejectedValueOnce(new Error('notification failed'));
    await expect(importFintelDesign(context, user, configuration, logoOf(PNG_LOGO), overwrite)).rejects.toThrow('notification failed');
    expect(vi.mocked(fintelDesignEditField).mock.calls[1][2]).toEqual({ id: 'previous-default-id', input: [{ key: 'default', value: [true] }] });
    expect(fintelDesignDelete).toHaveBeenCalledWith(context, user, 'new-design-id');
    expect(vi.mocked(fintelDesignEditField).mock.invocationCallOrder[1]).toBeLessThan(vi.mocked(fintelDesignDelete).mock.invocationCallOrder[0]);

    // The previous default cannot be given back: the design stays the default, never a platform without one
    vi.mocked(fintelDesignDelete).mockClear();
    vi.mocked(fintelDesignEditField).mockRejectedValueOnce(new Error('notification failed')).mockRejectedValueOnce(new Error('still down'));
    await expect(importFintelDesign(context, user, configuration, logoOf(PNG_LOGO), overwrite)).rejects.toThrow('notification failed');
    expect(fintelDesignDelete).not.toHaveBeenCalled();

    // The edit failed before making the design the default: deleted, the previous default untouched
    vi.mocked(fintelDesignEditField).mockReset().mockRejectedValueOnce(new Error('storage down'));
    vi.mocked(storeLoadById).mockImplementation(async (_ctx, _user, id) => (id === 'new-design-id' ? { id, default: false } : undefined) as never);
    await expect(importFintelDesign(context, user, configuration, logoOf(PNG_LOGO), overwrite)).rejects.toThrow('storage down');
    expect(fintelDesignEditField).toHaveBeenCalledTimes(1);
    expect(fintelDesignDelete).toHaveBeenCalledWith(context, user, 'new-design-id');
  });

  it('refuses a logo that is too large or is not an image, whatever the mode', async () => {
    expect(await importFintelDesign(context, user, configuration, logoOf(null), overwrite)).toMatchObject({ status: 'failed', code: 'logo_too_large' });
    expect(await importFintelDesign(context, user, configuration, logoOf(Buffer.from('<html></html>')), copy)).toMatchObject({ status: 'failed', code: 'logo_invalid' });
    expect(addFintelDesign).not.toHaveBeenCalled();
  });

  it('refuses a design that exists when it is added', async () => {
    withExisting(defaultFintelDesign);
    expect(await importFintelDesign(context, user, configuration, undefined, { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists', exists: true });
  });

  it('skips a design the platform has as it is, its logo included', async () => {
    withExisting(defaultFintelDesign);
    expect(await importFintelDesign(context, user, configuration, logoOf(PNG_LOGO), overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged', reason: 'Already up to date', exists: true });
    expect(readFintelDesignLogo).toHaveBeenCalledWith(defaultFintelDesign);
    expect(fintelDesignEditField).not.toHaveBeenCalled();
  });

  it('overwrites the values that differ and the logo when it differs, and leaves a value the bundle does not give untouched', async () => {
    withExisting({ ...defaultFintelDesign, name: 'Old name', gradiantToColor: '#123456' } as BasicStoreEntityFintelDesign);
    vi.mocked(readFintelDesignLogo).mockResolvedValue(Buffer.from('another logo'));
    const { description: _, textColor: __, ...partial } = configuration;
    expect(await importFintelDesign(context, user, partial, logoOf(PNG_LOGO), { ...overwrite, dryRun: true })).toMatchObject({ status: 'overwritten', exists: true });
    expect(fintelDesignEditField).not.toHaveBeenCalled();
    expect(await importFintelDesign(context, user, partial, logoOf(PNG_LOGO), overwrite)).toMatchObject({ status: 'overwritten', exists: true });
    const [[, , { id, file, input }]] = vi.mocked(fintelDesignEditField).mock.calls;
    expect(id).toBe(defaultFintelDesign.id);
    expect(input).toEqual([{ key: 'name', value: ['Filigran report'] }, { key: 'gradiantToColor', value: ['#001bda'] }]);
    expect((await readUpload(file)).content).toEqual(PNG_LOGO);
  });

  it('leaves a value the bundle gives as null untouched, as it does for one it does not give', async () => {
    const nulls = { ...configuration, description: null, gradiantFromColor: null, gradiantToColor: null, textColor: null };
    withExisting(defaultFintelDesign);
    expect(await importFintelDesign(context, user, nulls, undefined, overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged' });
    // With a change: the change only, never a null value
    withExisting({ ...defaultFintelDesign, name: 'Old name' } as BasicStoreEntityFintelDesign);
    expect(await importFintelDesign(context, user, nulls, undefined, overwrite)).toMatchObject({ status: 'overwritten' });
    expect(vi.mocked(fintelDesignEditField).mock.calls[0][2].input).toEqual([{ key: 'name', value: ['Filigran report'] }]);
  });

  it('keeps the free name of a copy within the length of a name, the suffix included', async () => {
    const longName = 'n'.repeat(FINTEL_DESIGN_NAME_MAX_LENGTH);
    withExisting({ ...defaultFintelDesign, name: longName } as BasicStoreEntityFintelDesign);
    withDesignsNamed({ ...defaultFintelDesign, name: longName } as BasicStoreEntityFintelDesign);
    const result = await importFintelDesign(context, user, { ...configuration, name: longName }, undefined, copy);
    expect(result.copyName).toBe(`${'n'.repeat(FINTEL_DESIGN_NAME_MAX_LENGTH - 4)} (1)`);
    expect(result.copyName).toHaveLength(FINTEL_DESIGN_NAME_MAX_LENGTH);
    expect(addFintelDesign).toHaveBeenCalledWith(context, user, expect.objectContaining({ name: result.copyName }));
  });

  it('refuses a copy when every free name is taken, and writes nothing', async () => {
    withExisting(defaultFintelDesign);
    // Every name asked for is taken by a design
    vi.mocked(fullEntitiesList).mockImplementation(async (_ctx, _user, _types, args) => {
      const name = (args as { filters: { filters: { values: string[] }[] } }).filters.filters[0].values[0];
      return [{ ...nightFintelDesign, name }] as never;
    });
    expect(await importFintelDesign(context, user, configuration, undefined, { ...copy, dryRun: true })).toMatchObject({
      status: 'failed', code: 'name_conflict', reason: 'Fintel design name already exists', exists: true,
    });
    expect(await importFintelDesign(context, user, configuration, undefined, copy)).toMatchObject({ status: 'failed', code: 'name_conflict' });
    expect(addFintelDesign).not.toHaveBeenCalled();
  });

  it('makes the design the default of the platform, and never takes the default away from a design', async () => {
    withExisting({ ...defaultFintelDesign, default: false } as BasicStoreEntityFintelDesign);
    await importFintelDesign(context, user, configuration, undefined, overwrite);
    expect(vi.mocked(fintelDesignEditField).mock.calls[0][2]).toEqual({ id: defaultFintelDesign.id, input: [{ key: 'default', value: [true] }], file: undefined });

    // The default design of the platform, not the default in the bundle: it stays the default
    withExisting(defaultFintelDesign);
    expect(await importFintelDesign(context, user, { ...configuration, default: false }, undefined, overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged' });
  });

  it('copies a design that exists under a free name and a new standard id, never as the default: the platform keeps its own', async () => {
    withExisting(defaultFintelDesign);
    withDesignsNamed(defaultFintelDesign, { ...nightFintelDesign, name: 'Filigran report (1)' } as BasicStoreEntityFintelDesign);
    const reservedNames = new Set<string>();
    expect(await importFintelDesign(context, user, configuration, undefined, { ...copy, dryRun: true, reservedNames })).toMatchObject({
      status: 'created',
      exists: true,
      copyName: 'Filigran report (2)',
      reason: 'Added as "Filigran report (2)"',
    });
    // The name a copy of the same dry run takes is not given twice
    expect(await importFintelDesign(context, user, configuration, undefined, { ...copy, dryRun: true, reservedNames })).toMatchObject({ copyName: 'Filigran report (3)' });
    expect(addFintelDesign).not.toHaveBeenCalled();

    await importFintelDesign(context, user, configuration, logoOf(PNG_LOGO), copy);
    const [[, , input]] = vi.mocked(addFintelDesign).mock.calls;
    expect(input).toMatchObject({ name: 'Filigran report (2)', default: false });
    expect(input).not.toHaveProperty('standard_id');
    // The logo only: the copy is not made the default, and the default of the platform is not even read
    expect(fintelDesignEditField).toHaveBeenCalledTimes(1);
    expect(vi.mocked(fintelDesignEditField).mock.calls[0][2].input).toEqual([]);
    expect(vi.mocked(fullEntitiesList).mock.calls.filter(([, , , args]) => JSON.stringify(args).includes('"default"'))).toHaveLength(0);
  });

  it('gives a copy the name the real import will give it, after a design an earlier item of the dry run creates or renames', async () => {
    const reservedNames = new Set<string>();
    const renamedIds = new Set<string>();
    const dryRun = { dryRun: true, reservedNames, renamedIds };
    // A new design takes the name "Filigran report (1)": the copy of the existing "Filigran report" after it cannot take it
    withDesignsNamed(defaultFintelDesign);
    expect(await importFintelDesign(context, user, { ...exportFintelDesign(nightFintelDesign), name: 'Filigran report (1)' }, undefined, { ...overwrite, ...dryRun }))
      .toMatchObject({ status: 'created' });
    withExisting(defaultFintelDesign);
    expect(await importFintelDesign(context, user, configuration, undefined, { ...copy, ...dryRun })).toMatchObject({ copyName: 'Filigran report (2)' });

    // An existing design renamed by an earlier item no longer holds its name, and its new name is taken
    reservedNames.clear();
    withExisting(nightFintelDesign);
    withDesignsNamed(nightFintelDesign);
    expect(await importFintelDesign(context, user, { ...exportFintelDesign(nightFintelDesign), name: 'Morning briefing' }, undefined, { ...overwrite, ...dryRun }))
      .toMatchObject({ status: 'overwritten' });
    expect(renamedIds).toEqual(new Set([nightFintelDesign.id]));
    withExisting(defaultFintelDesign);
    const nightCopy = { ...configuration, name: 'Night briefing' };
    expect(await importFintelDesign(context, user, nightCopy, undefined, { ...copy, ...dryRun })).toMatchObject({ copyName: 'Night briefing', reason: undefined });
    expect(await importFintelDesign(context, user, { ...configuration, name: 'Morning briefing' }, undefined, { ...copy, ...dryRun }))
      .toMatchObject({ copyName: 'Morning briefing (1)' });

    // Another design with the same name keeps it: a rename frees the name of the renamed design only
    reservedNames.clear();
    withDesignsNamed(nightFintelDesign, { ...defaultFintelDesign, name: 'Night briefing' } as BasicStoreEntityFintelDesign);
    expect(await importFintelDesign(context, user, nightCopy, undefined, { ...copy, ...dryRun })).toMatchObject({ copyName: 'Night briefing (1)' });
    expect(addFintelDesign).not.toHaveBeenCalled();
    expect(fintelDesignEditField).not.toHaveBeenCalled();
  });

  it('copies a design that does not exist under its own name and standard id', async () => {
    withDesignsNamed(defaultFintelDesign);
    expect(await importFintelDesign(context, user, configuration, undefined, copy)).toMatchObject({ status: 'created', exists: false, copyName: 'Filigran report', reason: undefined });
    // The design of the bundle itself: the default when it is the default of the bundle, as a first import
    expect(addFintelDesign).toHaveBeenCalledWith(context, user, expect.objectContaining({ name: 'Filigran report', standard_id: defaultFintelDesign.standard_id, default: true }));
  });
});
