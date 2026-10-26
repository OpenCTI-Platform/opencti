// Imports that changed nothing, remembered: when merging an input into an object left the object as it was, the
// identity index keeps a fingerprint of that merge with the version of the object (its _seq_no and _primary_term).
// The same merge on the same version is answered "unchanged" without computing it again, and without reading the
// refs it would compare. Anything that could change today's answer is in the fingerprint or moves the version:
//  - the object: any write to it (an edit by hand, another feed, the settler) gives it a new version;
//  - the input, once prepared and resolved (refs by id, type, and what markings are compared on);
//  - the user, as the platform holds it (rights, confidence, markings, organizations), and the request's synchro
//    flags;
//  - the platform: version, Enterprise Edition, platform organization, marking definitions, workflow statuses,
//    and the entity settings of the type.
// Preparing, resolving and the access checks before the merge still run, as today. A merge that read state outside
// these (aliases owned by other objects, individuals linked to users) or that moves files (embedded images) is not
// remembered.
import { createHash } from 'node:crypto';
import type { AuthContext, AuthUser } from '../../types/user';
import { elRawBulk, elRawMget } from '../../database/engine';
import { getEntitiesListFromCache, getEntityFromCache } from '../../database/cache';
import { isEnterpriseEditionFromSettings } from '../../enterprise-edition/ee';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_STATUS } from '../../schema/internalObject';
import { MARKDOWN_FIELD_KEY_SET } from '../../database/markdown-embedded-images';
import { PLATFORM_VERSION } from '../../config/conf';
import { SYSTEM_USER } from '../../utils/access';
import { lockfreeContext } from './context';
import { deterministicId, IDENTITY_INDEX } from './identity';
import type { RawDoc } from './load';

export interface Version { seq_no: number; primary_term: number }

export const versionOf = (raw: RawDoc): Version => ({ seq_no: raw._seq_no, primary_term: raw._primary_term });

const sha = (value: string) => createHash('sha256').update(value).digest('hex');

// Keys sorted; a resolved ref (an element, below the top level) as what the merge reads of it
const canonical = (value: any, depth = 0): any => {
  if (Array.isArray(value)) return value.map((item) => canonical(item, depth + 1));
  if (value instanceof Date) return value.toISOString();
  if (value && typeof value === 'object') {
    if (depth > 0 && typeof value.internal_id === 'string' && value.entity_type) {
      return [value.internal_id, value.entity_type, value.definition_type ?? null, value.x_opencti_order ?? null];
    }
    return Object.keys(value).sort().filter((key) => value[key] !== undefined).map((key) => [key, canonical(value[key], depth + 1)]);
  }
  return value;
};

const hashes = new WeakMap<object, string>();
const hashOnce = (value: object, compute: () => string) => {
  let hash = hashes.get(value);
  if (!hash) {
    hash = compute();
    hashes.set(value, hash);
  }
  return hash;
};

// What every fingerprint of a chunk shares: the platform, the user and the request
export const chunkEpoch = async (context: AuthContext, user: AuthUser) => {
  const [settings, markings, statuses] = await Promise.all([
    getEntityFromCache<any>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS),
    getEntitiesListFromCache<any>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION),
    getEntitiesListFromCache<any>(context, SYSTEM_USER, ENTITY_TYPE_STATUS),
  ]);
  const { origin: _, ...userState } = user;
  return sha(JSON.stringify([
    PLATFORM_VERSION,
    isEnterpriseEditionFromSettings(settings),
    settings?.platform_organization ?? null,
    hashOnce(markings, () => sha(JSON.stringify(canonical(markings.map((marking: any) => [marking.internal_id, marking.definition_type, marking.x_opencti_order]))))),
    hashOnce(statuses, () => sha(JSON.stringify(statuses))),
    hashOnce(user, () => sha(JSON.stringify(userState))),
    context.synchronizedUpsert ?? null,
    context.eventId ?? null,
  ]));
};

// The fingerprint of merging a patch into an object of a type, or undefined when such a merge is never remembered
export const fingerprintOf = (epoch: string, type: string, entitySetting: any, patch: Record<string, any>) => {
  if (patch.upsertOperations?.length > 0) return undefined; // resolved again inside the merge
  const embedsImages = Object.entries(patch).some(([key, value]) => MARKDOWN_FIELD_KEY_SET.has(key) && typeof value === 'string' && value.includes('data:'));
  if (embedsImages) return undefined;
  const setting = entitySetting ? hashOnce(entitySetting, () => sha(JSON.stringify(canonical(entitySetting)))) : null;
  return sha(JSON.stringify([epoch, type, setting, canonical(patch)]));
};

const docId = (objectId: string, fingerprint: string) => deterministicId(`unchanged|${objectId}|${fingerprint}`);
const entryKey = (objectId: string, fingerprint: string) => `${objectId}|${fingerprint}`;

// The versions on which each (object, fingerprint) was found to change nothing
export const readUnchanged = async (entries: { objectId: string; fingerprint: string }[]) => {
  const out = new Map<string, Version>();
  const unique = [...new Map(entries.map((entry) => [entryKey(entry.objectId, entry.fingerprint), entry])).values()];
  if (unique.length === 0) return out;
  const response: any = await elRawMget({ docs: unique.map((entry) => ({ _index: IDENTITY_INDEX, _id: docId(entry.objectId, entry.fingerprint) })) });
  response.docs.forEach((doc: any, i: number) => {
    if (!doc.found) return;
    const { objectId, fingerprint } = unique[i];
    out.set(entryKey(objectId, fingerprint), { seq_no: doc._source.seq_no, primary_term: doc._source.primary_term });
  });
  return out;
};

export const isUnchangedOn = (known: Map<string, Version>, objectId: string, fingerprint: string | undefined, version: Version | undefined) => {
  if (!fingerprint || !version) return false;
  const recorded = known.get(entryKey(objectId, fingerprint));
  return recorded?.seq_no === version.seq_no && recorded?.primary_term === version.primary_term;
};

export const recordUnchanged = async (entries: { objectId: string; fingerprint: string; version: Version }[]) => {
  if (entries.length === 0) return;
  const body = entries.flatMap((entry) => [
    { index: { _index: IDENTITY_INDEX, _id: docId(entry.objectId, entry.fingerprint) } },
    { unchanged_of: entry.objectId, seq_no: entry.version.seq_no, primary_term: entry.version.primary_term },
  ]);
  await elRawBulk(lockfreeContext, { refresh: false, body });
};
