import { describe, expect, it, vi } from 'vitest';
import {
  CONFIG_PRESET_IMPORT_MAX_TOTAL_SIZE,
  readConfigPresetBundle,
  restoreConfigPresetBundle,
  createConfigPresetBundleSnapshot,
} from '../../../../../src/modules/configPreset/import/configPreset-import-bundle';
import { buildZip, itemFile, metadataFile, validBundleFiles } from '../../../../utils/configPresetBundle';

const ID = '3f1d0c4e-7a52-4b8e-9f3a-1c2d3e4f5a6b';
const exclusionList = (id: string, attachment: string) => ({
  [`customization/exclusion_lists/${id}.json`]: JSON.stringify({
    openCTI_version: '0.0.1',
    type: 'customization.exclusionLists',
    id,
    configuration: { name: `DNS ${id}`, exclusion_list_entity_types: ['IPv4-Addr'] },
    attachment,
  }),
});
// The bundle the way the importers see it, without what cannot be compared (a function)
const withoutReaders = (bundle: Awaited<ReturnType<typeof readConfigPresetBundle>>) => ({
  ...bundle,
  items: bundle.items.map(({ attachment, ...item }) => ({ ...item, attachment: attachment?.path })),
});

// The uncompressed size of each attachment of the central directory (offset 24 of a header) is set to 1: the zip lies, and only the bytes
// really read can stop it
const underdeclare = (zip: Buffer) => {
  for (let offset = zip.indexOf(Buffer.from('PK\x01\x02', 'latin1')); offset >= 0; offset = zip.indexOf(Buffer.from('PK\x01\x02', 'latin1'), offset + 4)) {
    const name = zip.subarray(offset + 46, offset + 46 + zip.readUInt16LE(offset + 28)).toString();
    if (name.endsWith('.txt')) {
      zip.writeUInt32LE(1, offset + 24);
    }
  }
  return zip;
};

describe('Snapshot of a config preset bundle', () => {
  it('gives back the bundle that was read from the zip', async () => {
    const files = { ...validBundleFiles(), 'other/not-an-item.json': JSON.stringify({ hello: 'world' }), 'README.txt': 'hello' };
    const zip = await buildZip(files);
    const fromSnapshot = restoreConfigPresetBundle(await createConfigPresetBundleSnapshot(zip), async () => zip);
    expect(withoutReaders(fromSnapshot)).toEqual(withoutReaders(await readConfigPresetBundle(zip)));
    expect(fromSnapshot.items).toHaveLength(3);
    expect(fromSnapshot.ignored.sort()).toEqual(['README.txt', 'other/not-an-item.json']);
  });

  it('keeps the dependencies, and a bundle name that is null', async () => {
    const zip = await buildZip({ ...validBundleFiles(), 'metadata.json': metadataFile(undefined, null) });
    const bundle = restoreConfigPresetBundle(await createConfigPresetBundleSnapshot(zip), async () => zip);
    expect(bundle.metadata.bundle_name).toBeNull();
    expect(bundle.dependencies).toEqual((await readConfigPresetBundle(zip)).dependencies);
  });

  it('gives each caller its own objects: what one of them changes is not seen by the next', async () => {
    const zip = await buildZip(validBundleFiles());
    const snapshot = await createConfigPresetBundleSnapshot(zip);
    const first = restoreConfigPresetBundle(snapshot, async () => zip);
    first.items[0].configuration.name = 'changed';
    first.items.pop();
    const second = restoreConfigPresetBundle(snapshot, async () => zip);
    expect(second.items).toHaveLength(3);
    expect(second.items[0].configuration.name).not.toEqual('changed');
  });

  it('is a Buffer much smaller than a zip of many files is slow to read: one text, whatever the number of items', async () => {
    const files = Object.fromEntries(Array.from({ length: 300 }, (_, i) => [`taxonomy/labels/${i}.json`, itemFile('taxonomy.labels', `label-${i}`, { value: `label-${i}`, color: '#336699' })]));
    const zip = await buildZip({ 'metadata.json': metadataFile(), ...files });
    const snapshot = await createConfigPresetBundleSnapshot(zip);
    expect(Buffer.isBuffer(snapshot)).toBe(true);
    expect(restoreConfigPresetBundle(snapshot, async () => zip).items).toHaveLength(300);
  });

  describe('the attachment of an item', () => {
    const TXT = `customization/exclusion_lists/${ID}.txt`;
    const buildZipWithList = () => buildZip({ 'metadata.json': metadataFile(), ...exclusionList(ID, TXT), [TXT]: '8.8.8.8\n1.1.1.1\n' });

    it('is read from the zip when an importer asks for it, and not before', async () => {
      const zip = await buildZipWithList();
      const openZip = vi.fn(async () => zip);
      const bundle = restoreConfigPresetBundle(await createConfigPresetBundleSnapshot(zip), openZip);
      expect(bundle.items).toHaveLength(1);
      expect(bundle.items[0].attachment?.path).toEqual(TXT);
      expect(bundle.ignored).toEqual([]);
      expect(openZip).not.toHaveBeenCalled();
      expect((await bundle.items[0].attachment!.read(1024))?.toString()).toEqual('8.8.8.8\n1.1.1.1\n');
      // An item reads it to be computed and again to be applied: the zip is opened once for the bundle
      expect((await bundle.items[0].attachment!.read(1024))?.toString()).toEqual('8.8.8.8\n1.1.1.1\n');
      expect(openZip).toHaveBeenCalledTimes(1);
    });

    it('is null when it is bigger than the limit the importer gives, as for a bundle read from a zip', async () => {
      const zip = await buildZipWithList();
      const bundle = restoreConfigPresetBundle(await createConfigPresetBundleSnapshot(zip), async () => zip);
      expect(await bundle.items[0].attachment!.read(4)).toBeNull();
    });

    it('counts against the limit of the extracted size, as when the zip was read', async () => {
      // Two attachments of 26 MB: each one is within the limit of 50 MB, both are not
      const size = Math.ceil(CONFIG_PRESET_IMPORT_MAX_TOTAL_SIZE / 2) + 1024 * 1024;
      const first = 'customization/exclusion_lists/a.txt';
      const second = 'customization/exclusion_lists/b.txt';
      const zip = underdeclare(await buildZip({
        'metadata.json': metadataFile(),
        ...exclusionList('a', first),
        ...exclusionList('b', second),
        [first]: Buffer.alloc(size, 'a'),
        [second]: Buffer.alloc(size, 'b'),
      }));
      const bundle = restoreConfigPresetBundle(await createConfigPresetBundleSnapshot(zip), async () => zip);
      expect(await bundle.items[0].attachment!.read(size)).toHaveLength(size);
      const error = await bundle.items[1].attachment!.read(size).catch((err) => err);
      expect(error.extensions?.data?.reason).toEqual('bundle_refused');
      expect(error.message).toContain('too large once extracted');
    });

    it('opens the zip again after a failure to open it', async () => {
      const zip = await buildZipWithList();
      const openZip = vi.fn<() => Promise<Buffer>>().mockRejectedValueOnce(new Error('storage down')).mockResolvedValue(zip);
      const bundle = restoreConfigPresetBundle(await createConfigPresetBundleSnapshot(zip), openZip);
      await expect(bundle.items[0].attachment!.read(1024)).rejects.toThrow('storage down');
      expect((await bundle.items[0].attachment!.read(1024))?.toString()).toEqual('8.8.8.8\n1.1.1.1\n');
    });
  });
});
