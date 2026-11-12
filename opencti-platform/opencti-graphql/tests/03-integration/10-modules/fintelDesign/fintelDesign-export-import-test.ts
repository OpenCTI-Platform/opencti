import { Readable } from 'node:stream';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
// @ts-expect-error unzipper ships no type declarations
import unzipper from 'unzipper';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess } from '../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import * as enterpriseEdition from '../../../../src/enterprise-edition/ee';
import { getClientBase } from '../../../../src/database/redis';
import { deleteFile } from '../../../../src/database/file-storage';
import { downloadFile } from '../../../../src/database/raw-file-storage';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { allFilesForPaths } from '../../../../src/modules/internal/document/document-domain';
import { addFintelDesign, fintelDesignDelete, fintelDesignEditField } from '../../../../src/modules/fintelDesign/fintelDesign-domain';
import { fintelDesignLogoStorageKey, readFintelDesignLogo } from '../../../../src/modules/fintelDesign/fintelDesign-logo';
import { type BasicStoreEntityFintelDesign, ENTITY_TYPE_FINTEL_DESIGN } from '../../../../src/modules/fintelDesign/fintelDesign-types';

// The real export and the real import engine on the fintel designs: the default design travels with any other one, and the logo as a file
// of the zip next to the JSON of its design. Names that no other test of the platform uses.
const DEFAULT_NAME = 'Config preset round trip default design';
const OTHER_NAME = 'Config preset round trip design';
const TARGET_DEFAULT_NAME = 'Config preset round trip target default design';
const LOGO = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from('config-preset-round-trip-logo')]);

const UPLOAD_MUTATION = gql`mutation FintelDesignRoundTripUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const EXPORT_MUTATION = gql`mutation FintelDesignRoundTripExport($selections: [ConfigPresetSelectionInput!]!) { configPresetExport(selections: $selections) { id } }`;
const IMPORT_MUTATION = gql`
  mutation FintelDesignRoundTripImport($file_id: ID!, $selections: [ConfigPresetSelectionInput!]!, $dry_run: Boolean) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: $dry_run) {
      results { type key status code reason label }
    }
  }
`;

const readStream = async (stream: unknown) => {
  const chunks: Buffer[] = [];
  for await (const chunk of stream as AsyncIterable<Buffer>) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
};
const allDesigns = () => fullEntitiesList<BasicStoreEntityFintelDesign>(testContext, ADMIN_USER, [ENTITY_TYPE_FINTEL_DESIGN]);
const designsNamed = async (name: string) => (await allDesigns()).filter((design) => design.name === name);
const loadDesign = async (name: string) => (await designsNamed(name))[0];
const deleteDesign = async (design: BasicStoreEntityFintelDesign) => {
  await fintelDesignDelete(testContext, ADMIN_USER, design.id);
  if (design.file_id) {
    await deleteFile(testContext, ADMIN_USER, design.file_id, { forceDelete: true }).catch(() => undefined);
  }
};
const runImport = async (zip: Buffer, selections: unknown[], dryRun: boolean) => {
  const uploaded = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(zip, 'fintel-designs.zip') } });
  const { data, errors } = await queryAsAdmin({
    query: IMPORT_MUTATION,
    variables: { file_id: uploaded.data?.configPresetImportUpload.id, selections, dry_run: dryRun },
  });
  expect(errors).toBeUndefined();
  return data?.configPresetImport.results as { type: string; key: string; status: string; code: string | null; reason: string | null; label: string }[];
};

describe('Fintel designs: export and import of the real zip', () => {
  let previousDefault: BasicStoreEntityFintelDesign | undefined;

  beforeAll(async () => {
    vi.spyOn(enterpriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(enterpriseEdition, 'isEnterpriseEditionUpToDate').mockResolvedValue(true);
    previousDefault = (await allDesigns()).find((design) => design.default);
  });

  afterAll(async () => {
    for (const name of [DEFAULT_NAME, `${DEFAULT_NAME} (1)`, OTHER_NAME, TARGET_DEFAULT_NAME]) {
      for (const design of await designsNamed(name)) {
        await deleteDesign(design);
      }
    }
    // The default design of the other tests of the platform is given back
    if (previousDefault) {
      await fintelDesignEditField(testContext, ADMIN_USER, { id: previousDefault.id, input: [{ key: 'default', value: [true] }] });
    }
    vi.restoreAllMocks();
  });

  afterEach(async () => {
    await queryAsAdmin({ query: gql`mutation FintelDesignRoundTripClear { configPresetImportSessionClear(delete_file: true) }` });
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`);
    const history = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history']);
    for (let i = 0; i < history.length; i += 1) {
      await deleteFile(testContext, ADMIN_USER, history[i].id, { forceDelete: true });
    }
  });

  it('exports the default design with any other one and its logo, imports them as they were, the default one as the default, then says they are up to date', async () => {
    const created = await addFintelDesign(testContext, ADMIN_USER, { name: DEFAULT_NAME, description: 'Round trip', gradiantFromColor: '#00020c', gradiantToColor: '#001bda', textColor: '#ffffff', default: true });
    const upload = Promise.resolve({ createReadStream: () => Readable.from(LOGO), filename: 'logo.png' });
    await fintelDesignEditField(testContext, ADMIN_USER, { id: created.id, file: upload as never });
    await addFintelDesign(testContext, ADMIN_USER, { name: OTHER_NAME, gradiantFromColor: '#123456', default: false });
    const defaultDesign = await loadDesign(DEFAULT_NAME);
    const otherDesign = await loadDesign(OTHER_NAME);
    // The key the export reads a logo from is the one it is stored under: both are defined by the module, nothing else ties them
    expect(defaultDesign.file_id).toBe(fintelDesignLogoStorageKey(defaultDesign.internal_id));

    // Only the other design is selected: the default one is exported with it
    const exported = await queryAsAdminWithSuccess({ query: EXPORT_MUTATION, variables: { selections: [{ type: 'fintelDesigns', items: [otherDesign.standard_id] }] } });
    const exportId = exported.data?.configPresetExport.id as string;
    const zip = await readStream(await downloadFile(exportId));
    await deleteFile(testContext, ADMIN_USER, exportId, { forceDelete: true });
    const directory = await unzipper.Open.buffer(zip);
    const entries: Record<string, Buffer> = {};
    for (let i = 0; i < directory.files.length; i += 1) {
      entries[directory.files[i].path] = await directory.files[i].buffer();
    }
    const designPath = (design: BasicStoreEntityFintelDesign) => `customization/fintel_designs/${design.standard_id}`;
    expect(Object.keys(entries).sort()).toEqual([
      `${designPath(defaultDesign)}.json`,
      `${designPath(defaultDesign)}.logo`,
      `${designPath(otherDesign)}.json`,
      'dependencies.json',
      'metadata.json',
    ].sort());
    expect(entries[`${designPath(defaultDesign)}.logo`]).toEqual(LOGO);
    expect(JSON.parse(entries['dependencies.json'].toString())).toEqual({
      'customization.fintelDesigns': { [otherDesign.standard_id]: { [defaultDesign.standard_id]: `${designPath(defaultDesign)}.json` } },
    });

    // Another platform: the designs do not exist there, and it has its own default design
    await deleteDesign(defaultDesign);
    await deleteDesign(otherDesign);
    await addFintelDesign(testContext, ADMIN_USER, { name: TARGET_DEFAULT_NAME, default: true });

    const selections = [{ type: 'fintelDesigns' }];
    const dry = await runImport(zip, selections, true);
    expect(dry.map(({ label, status }) => `${label}:${status}`).sort()).toEqual([`${DEFAULT_NAME}:CREATED`, `${OTHER_NAME}:CREATED`].sort());
    expect(await designsNamed(DEFAULT_NAME)).toHaveLength(0);

    const real = await runImport(zip, selections, false);
    expect(real.map(({ label, status }) => `${label}:${status}`).sort()).toEqual([`${DEFAULT_NAME}:CREATED`, `${OTHER_NAME}:CREATED`].sort());
    const restored = await loadDesign(DEFAULT_NAME);
    expect(restored).toMatchObject({ standard_id: defaultDesign.standard_id, description: 'Round trip', gradiantToColor: '#001bda', textColor: '#ffffff', default: true });
    expect(await readFintelDesignLogo(restored)).toEqual(LOGO);
    expect(await loadDesign(OTHER_NAME)).toMatchObject({ standard_id: otherDesign.standard_id, gradiantFromColor: '#123456', default: false });
    // The default design of the bundle is the only default of the platform
    expect((await allDesigns()).filter((design) => design.default).map((design) => design.name)).toEqual([DEFAULT_NAME]);

    const again = await runImport(zip, selections, false);
    expect(again.map(({ status, code }) => `${status}:${code}`)).toEqual(['SKIPPED:unchanged', 'SKIPPED:unchanged']);
    expect(await designsNamed(DEFAULT_NAME)).toHaveLength(1);

    // A copy of the default design that exists is another design, under a free name, and it is the default
    const copied = await runImport(zip, [{ type: 'fintelDesigns', items: [defaultDesign.standard_id], item_modes: [{ key: defaultDesign.standard_id, mode: 'COPY' }] }], false);
    expect(copied.map(({ label, status, reason }) => [label, status, reason])).toEqual([[DEFAULT_NAME, 'CREATED', `Added as "${DEFAULT_NAME} (1)"`]]);
    const copy = await loadDesign(`${DEFAULT_NAME} (1)`);
    expect(copy.standard_id).not.toBe(defaultDesign.standard_id);
    expect(await readFintelDesignLogo(copy)).toEqual(LOGO);
    expect((await allDesigns()).filter((design) => design.default).map((design) => design.name)).toEqual([`${DEFAULT_NAME} (1)`]);
  });
});
