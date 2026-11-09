import { pipeline, type Readable, Transform } from 'node:stream';
import semver from 'semver';
// @ts-expect-error unzipper ships no type declarations
import unzipper from 'unzipper';
import { z } from 'zod';
import { PLATFORM_VERSION } from '../../../config/conf';
import { FunctionalError } from '../../../config/errors';
import { CONFIG_PRESET_DEPENDENCIES_FILE, CONFIG_PRESET_METADATA_FILE } from '../configPreset-utils';
import { CONFIG_PRESET_FAMILIES, configPresetFamilyType } from '../configPreset-registry';
import {
  CONFIG_PRESET_REASON_BUNDLE_REFUSED,
  type ConfigPresetBundle,
  type ConfigPresetBundleAttachment,
  type ConfigPresetBundleItem,
  type ConfigPresetBundleMetadata,
  configPresetPlanKey,
} from './configPreset-import-types';

// Limits of a bundle, enforced on the bytes really read and never on the sizes declared in the zip
export const CONFIG_PRESET_IMPORT_MAX_ZIP_SIZE = 50 * 1024 * 1024;
export const CONFIG_PRESET_IMPORT_MAX_ENTRY_SIZE = 5 * 1024 * 1024;
export const CONFIG_PRESET_IMPORT_MAX_TOTAL_SIZE = 50 * 1024 * 1024;

export const bundleRefused = (message: string, data: Record<string, unknown> = {}) => {
  return FunctionalError(message, { ...data, reason: CONFIG_PRESET_REASON_BUNDLE_REFUSED });
};

// The stream through a counter that fails as soon as more than the limit goes through, so an oversized upload is not stored.
// A pipeline, not a pipe: a refusal destroys the source too, otherwise the temporary file of the upload stays on disk
export const limitStream = (source: Readable, limit: number): Readable => {
  let size = 0;
  const counter = new Transform({
    transform(chunk, _encoding, callback) {
      size += chunk.length;
      callback(size > limit ? bundleRefused('The configuration bundle is too large', { limit }) : null, chunk);
    },
  });
  return pipeline(source, counter, () => undefined);
};

// Reads a stream through a counter: a stream above the limit is refused as soon as it goes over
export const readStreamWithLimit = async (stream: AsyncIterable<Buffer | string>, limit: number, tooLarge: () => Error) => {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stream) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > limit) {
      throw tooLarge();
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
};

const metadataSchema = z.object({
  openCTI_version: z.string(),
  generated_at: z.string(),
  bundle_name: z.string().nullish().transform((name) => name ?? null),
});
const dependenciesSchema = z.record(z.string(), z.record(z.string(), z.record(z.string(), z.string())));
const itemFileSchema = z.object({ type: z.string(), id: z.string(), configuration: z.record(z.string(), z.unknown()), attachment: z.string().optional() });

// A bundle from a more recent platform is refused; a -dev or -rc suffix is ignored and an unreadable version is refused.
// Not isCompatibleVersionWithMinimal: it has no coerce and throws on a non-semver string.
const checkBundleVersion = (bundleVersion: string) => {
  const bundle = semver.coerce(bundleVersion);
  const platform = semver.coerce(PLATFORM_VERSION);
  if (!bundle || !platform) {
    throw bundleRefused('The version of the configuration bundle cannot be read', { version: bundleVersion });
  }
  if (semver.gt(bundle, platform)) {
    throw bundleRefused('The configuration bundle comes from a more recent platform', { version: bundleVersion, platform_version: PLATFORM_VERSION });
  }
};

const parseJson = (path: string, content: Buffer) => {
  try {
    return JSON.parse(content.toString('utf8'));
  } catch {
    throw bundleRefused('The configuration bundle holds an invalid JSON file', { path });
  }
};

// `<group id>.<family id>` -> the family, looked up by its bare id and checked against its group
const findItemFamily = (type: string) => {
  const dot = type.indexOf('.');
  const familyId = dot >= 0 ? type.slice(dot + 1) : type;
  const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === familyId);
  return family && configPresetFamilyType(family) === type ? family : undefined;
};

// The attachments are read when an importer asks for them: what they add to the extracted size counts against the same limit as the JSON
// files. An attachment is counted the first time it is read only: an item reads it to be computed and again to be applied, and nothing
// is kept of it between the two, so the memory stays bounded by one attachment.
const toBundleAttachment = (path: string, entry: { stream: () => AsyncIterable<Buffer | string> }, extracted: { size: number }): ConfigPresetBundleAttachment => {
  let counted = false;
  return {
    path,
    read: async (limit) => {
      const tooLarge = new Error('too large');
      let content: Buffer | null;
      try {
        content = await readStreamWithLimit(entry.stream(), limit, () => tooLarge);
      } catch (err) {
        if (err !== tooLarge) {
          throw err;
        }
        content = null;
      }
      if (!counted) {
        counted = true;
        // A refused file was read up to the limit: it counts for that much, or a bundle of such files is never stopped
        extracted.size += content ? content.length : limit;
        if (extracted.size > CONFIG_PRESET_IMPORT_MAX_TOTAL_SIZE) {
          throw bundleRefused('The configuration bundle is too large once extracted');
        }
      }
      return content;
    },
  };
};

// Reads a zip in memory, nothing is written to disk and entry names are never used as paths
export const readConfigPresetBundle = async (zip: Buffer): Promise<ConfigPresetBundle> => {
  let directory;
  try {
    directory = await unzipper.Open.buffer(zip);
  } catch {
    throw bundleRefused('The file is not a valid zip archive');
  }
  let metadata: ConfigPresetBundleMetadata | undefined;
  let dependencies: ConfigPresetBundle['dependencies'] = {};
  const items: ConfigPresetBundleItem[] = [];
  const ignored: string[] = [];
  // The entries that are not JSON, by path: the attachment an item points to is read when its importer asks for it
  const otherEntries = new Map<string, { stream: () => AsyncIterable<Buffer | string>; uncompressedSize: number }>();
  const attachmentPaths = new Map<string, string>();
  const extracted = { size: 0 };
  for (let i = 0; i < directory.files.length; i += 1) {
    const entry = directory.files[i];
    if (entry.type !== 'Directory') {
      if (!entry.path.endsWith('.json')) {
        otherEntries.set(entry.path, entry);
      } else {
        const content = await readStreamWithLimit(entry.stream(), CONFIG_PRESET_IMPORT_MAX_ENTRY_SIZE, () => {
          return bundleRefused('A file of the configuration bundle is too large', { path: entry.path });
        });
        extracted.size += content.length;
        if (extracted.size > CONFIG_PRESET_IMPORT_MAX_TOTAL_SIZE) {
          throw bundleRefused('The configuration bundle is too large once extracted');
        }
        const json = parseJson(entry.path, content);
        if (entry.path === CONFIG_PRESET_METADATA_FILE) {
          const parsed = metadataSchema.safeParse(json);
          if (!parsed.success) {
            throw bundleRefused('The metadata of the configuration bundle is invalid');
          }
          metadata = parsed.data;
        } else if (entry.path === CONFIG_PRESET_DEPENDENCIES_FILE) {
          const parsed = dependenciesSchema.safeParse(json);
          if (!parsed.success) {
            throw bundleRefused('The dependencies of the configuration bundle are invalid');
          }
          dependencies = parsed.data;
        } else {
          const parsed = itemFileSchema.safeParse(json);
          const family = parsed.success ? findItemFamily(parsed.data.type) : undefined;
          if (!parsed.success || !family) {
            ignored.push(entry.path);
          } else if (!family.importer) {
            // A family without importer is reported as not importable
            ignored.push(entry.path);
          } else {
            if (items.some((item) => item.type === family.id && item.id === parsed.data.id)) {
              throw bundleRefused('The configuration bundle holds the same item twice', { type: parsed.data.type, id: parsed.data.id });
            }
            items.push({ type: family.id, id: parsed.data.id, path: entry.path, configuration: parsed.data.configuration });
            if (parsed.data.attachment) {
              attachmentPaths.set(entry.path, parsed.data.attachment);
            }
          }
        }
      }
    }
  }
  if (!metadata) {
    throw bundleRefused(`The configuration bundle has no valid ${CONFIG_PRESET_METADATA_FILE}`);
  }
  checkBundleVersion(metadata.openCTI_version);
  // The attachment of an item is the entry of the zip at the path its JSON gives, never a path of the disk. A path that is no entry gives no
  // attachment, and an entry serves one item only.
  const claimed = new Set<string>();
  let declaredSize = 0;
  for (let i = 0; i < items.length; i += 1) {
    const attachmentPath = attachmentPaths.get(items[i].path);
    const entry = attachmentPath ? otherEntries.get(attachmentPath) : undefined;
    if (attachmentPath && entry && !claimed.has(attachmentPath)) {
      claimed.add(attachmentPath);
      // The size the zip declares cannot be trusted, the bytes really read are the limit: it only refuses at once a bundle that cannot be
      // read to the end, instead of failing in the middle of an import, after some of its items were written
      declaredSize += entry.uncompressedSize;
      if (extracted.size + declaredSize > CONFIG_PRESET_IMPORT_MAX_TOTAL_SIZE) {
        throw bundleRefused('The configuration bundle is too large once extracted');
      }
      items[i].attachment = toBundleAttachment(attachmentPath, entry, extracted);
    }
  }
  otherEntries.forEach((_entry, path) => {
    if (!claimed.has(path)) {
      ignored.push(path);
    }
  });
  return { metadata, items, dependencies, ignored };
};

export interface ConfigPresetItemKey {
  type: string;
  id: string;
}

// The items the given ones depend on, one level as the export writes it, with a visited set: a cycle or an item
// missing from the zip does not matter. Dependencies come first, then the selection, each in the order found.
export const resolveBundleDependencies = (bundle: ConfigPresetBundle, selection: ConfigPresetItemKey[]): ConfigPresetBundleItem[] => {
  const byKey = new Map(bundle.items.map((item) => [configPresetPlanKey(item.type, item.id), item]));
  const byPath = new Map(bundle.items.map((item) => [item.path, item]));
  const ordered: ConfigPresetBundleItem[] = [];
  const visited = new Set<string>();
  const visit = (key: ConfigPresetItemKey) => {
    const planKey = configPresetPlanKey(key.type, key.id);
    const item = byKey.get(planKey);
    if (item && !visited.has(planKey)) {
      visited.add(planKey);
      const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === item.type);
      const paths = Object.values(bundle.dependencies[family ? configPresetFamilyType(family) : item.type]?.[item.id] ?? {});
      paths.forEach((path) => {
        const dependency = byPath.get(path);
        if (dependency) {
          visit(dependency);
        }
      });
      ordered.push(item);
    }
  };
  selection.forEach(visit);
  return ordered;
};
