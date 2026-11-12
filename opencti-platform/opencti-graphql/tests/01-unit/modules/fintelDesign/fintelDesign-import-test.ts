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
}));
vi.mock('../../../../src/modules/fintelDesign/fintelDesign-logo', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/fintelDesign/fintelDesign-logo')>()),
  readFintelDesignLogo: vi.fn(),
}));

import { fullEntitiesList, storeLoadById } from '../../../../src/database/middleware-loader';
import { addFintelDesign, fintelDesignEditField } from '../../../../src/modules/fintelDesign/fintelDesign-domain';
import { FINTEL_DESIGN_LOGO_MAX_SIZE, fintelDesignLogoExtension, readFintelDesignLogo } from '../../../../src/modules/fintelDesign/fintelDesign-logo';
import { exportFintelDesign } from '../../../../src/modules/fintelDesign/fintelDesign-export';
import { importFintelDesign } from '../../../../src/modules/fintelDesign/fintelDesign-import';
import { fintelDesignImportSchema } from '../../../../src/modules/fintelDesign/fintelDesign-import-schema';
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

  it('refuses unknown keys, another standard id, a color that is not hex and a blank name', () => {
    expect(fintelDesignImportSchema.safeParse({ ...configuration, file_id: 'fintelDesigns/x' }).success).toBe(false);
    expect(fintelDesignImportSchema.safeParse({ ...configuration, standard_id: 'theme--2c5e8f1a-4b3d-5e6f-8a9b-0c1d2e3f4a5b' }).success).toBe(false);
    expect(fintelDesignImportSchema.safeParse({ ...configuration, textColor: 'red;}' }).success).toBe(false);
    expect(fintelDesignImportSchema.safeParse({ ...configuration, name: '  ' }).success).toBe(false);
    expect(fintelDesignImportSchema.safeParse({ ...configuration, gradiantFromColor: null, textColor: '' }).success).toBe(true);
  });
});

describe('Fintel design logo format', () => {
  it('recognizes the image formats from their bytes, an SVG after its prolog, and nothing else', () => {
    expect(fintelDesignLogoExtension(PNG_LOGO)).toBe('png');
    expect(fintelDesignLogoExtension(Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00]))).toBe('jpg');
    expect(fintelDesignLogoExtension(Buffer.from('GIF89a....'))).toBe('gif');
    expect(fintelDesignLogoExtension(Buffer.from('RIFF\u0000\u0000\u0000\u0000WEBPVP8 '))).toBe('webp');
    expect(fintelDesignLogoExtension(Buffer.from('﻿<?xml version="1.0"?>\n<!-- logo -->\n<svg xmlns="http://www.w3.org/2000/svg"></svg>'))).toBe('svg');
    expect(fintelDesignLogoExtension(Buffer.from('<html><body>svg</body></html>'))).toBeUndefined();
    expect(fintelDesignLogoExtension(Buffer.from('not an image'))).toBeUndefined();
  });
});

describe('Fintel design import', () => {
  it('refuses an invalid configuration without reading the platform', async () => {
    const result = await importFintelDesign(context, user, { name: 'No id' }, undefined, overwrite);
    expect(result).toMatchObject({ status: 'failed', code: 'invalid', exists: false });
    expect(storeLoadById).not.toHaveBeenCalled();
  });

  it('creates a design that does not exist under its standard id, as the default, then stores its logo, and writes nothing on a dry run', async () => {
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
      default: true,
      standard_id: defaultFintelDesign.standard_id,
    });
    const [[, , { id, file, input }]] = vi.mocked(fintelDesignEditField).mock.calls;
    expect([id, input]).toEqual(['new-design-id', undefined]);
    // The domain checks that the file is an image from its extension: the one of the bytes
    expect(await readUpload(file)).toEqual({ content: PNG_LOGO, filename: 'logo.png' });
  });

  it('creates a design without logo when the bundle has none, and not as the default when it is not', async () => {
    expect(await importFintelDesign(context, user, exportFintelDesign(nightFintelDesign), undefined, overwrite)).toMatchObject({ status: 'created' });
    expect(addFintelDesign).toHaveBeenCalledWith(context, user, expect.objectContaining({ name: 'Night briefing', default: false, textColor: undefined, description: undefined }));
    expect(fintelDesignEditField).not.toHaveBeenCalled();
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

  it('makes the design the default of the platform, and never takes the default away from a design', async () => {
    withExisting({ ...defaultFintelDesign, default: false } as BasicStoreEntityFintelDesign);
    await importFintelDesign(context, user, configuration, undefined, overwrite);
    expect(vi.mocked(fintelDesignEditField).mock.calls[0][2]).toEqual({ id: defaultFintelDesign.id, input: [{ key: 'default', value: [true] }], file: undefined });

    // The default design of the platform, not the default in the bundle: it stays the default
    withExisting(defaultFintelDesign);
    expect(await importFintelDesign(context, user, { ...configuration, default: false }, undefined, overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged' });
  });

  it('copies a design that exists under a free name and a new standard id, and as the default when it is the default of the bundle', async () => {
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
    expect(input).toMatchObject({ name: 'Filigran report (2)', default: true });
    expect(input).not.toHaveProperty('standard_id');
    expect(fintelDesignEditField).toHaveBeenCalledTimes(1);
  });

  it('copies a design that does not exist under its own name and standard id', async () => {
    withDesignsNamed(defaultFintelDesign);
    expect(await importFintelDesign(context, user, configuration, undefined, copy)).toMatchObject({ status: 'created', exists: false, copyName: 'Filigran report', reason: undefined });
    expect(addFintelDesign).toHaveBeenCalledWith(context, user, expect.objectContaining({ name: 'Filigran report', standard_id: defaultFintelDesign.standard_id }));
  });
});
