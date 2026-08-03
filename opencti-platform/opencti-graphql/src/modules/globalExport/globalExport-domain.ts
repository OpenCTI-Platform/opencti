import * as archiver from 'archiver';
import pjson from '../../../package.json';
import type { AuthContext, AuthUser } from '../../types/user';
import { BYPASS, isUserHasCapability } from '../../utils/access';
import { ForbiddenAccess } from '../../config/errors';
import { getGlobalExportEntry } from './globalExport-registry';

const slugify = (name: string) => (name ?? 'unnamed')
  .toLowerCase()
  .replace(/[^a-z0-9-_]+/g, '-')
  .replace(/^-+|-+$/g, '')
  .slice(0, 80) || 'unnamed';

/**
 * Builds the configuration export ZIP for the given selection and returns it
 * base64-encoded, following the same pattern as a single-entity export
 * function (returns a string) - the frontend decodes it and triggers the
 * browser download, exactly like existing per-entity export buttons.
 */
export const generateGlobalConfigurationExport = async (
  context: AuthContext,
  user: AuthUser,
  selectedKeys: string[],
): Promise<string> => {
  if (!isUserHasCapability(user, BYPASS)) {
    throw ForbiddenAccess();
  }

  const archive = archiver('zip', { zlib: { level: 9 } });
  const chunks: Buffer[] = [];
  archive.on('data', (chunk) => chunks.push(chunk));

  const counts: Record<string, number> = {};
  const uniqueKeys = Array.from(new Set(selectedKeys));

  for (let i = 0; i < uniqueKeys.length; i += 1) {
    const key = uniqueKeys[i];
    const entry = getGlobalExportEntry(key); // throws loudly on unknown/unwired key

    const entities = await entry.listAll(context, user);
    counts[key] = entities.length;

    for (let j = 0; j < entities.length; j += 1) {
      const entity = entities[j];

      const exportedJson = await entry.exportOne(context, user, entity);
      const filename = `${entry.folder}/${entry.filePrefix}-${slugify(entity.name)}-${entity.id}.json`;
      archive.append(exportedJson, { name: filename });
    }
  }

  const meta = {
    openCTI_version: pjson.version,
    generated_at: new Date().toISOString(),
    generated_by: user.id,
    categories: uniqueKeys,
    counts,
  };
  archive.append(JSON.stringify(meta, null, 2), { name: 'meta.json' });

  await archive.finalize();
  const zipBuffer = Buffer.concat(chunks);
  return zipBuffer.toString('base64');
};
