import { findByIds } from './hunt-loaders';
import { v4 as uuidv4 } from 'uuid';
import type { FileHandle } from 'fs/promises';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject } from '../../types/stix-2-1-common';
import { FunctionalError } from '../../config/errors';
import { storeLoadByIdWithRefs } from '../../database/middleware';
import { fullEntitiesList } from '../../database/middleware-loader';
import { convertStoreToStix_2_1 } from '../../database/stix-2-1-converter';
import { STIX_SPEC_VERSION } from '../../database/stix';
import { generateStandardId } from '../../schema/identifier';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../schema/stixDomainObject';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_HUNT } from '../../types/stix-2-1-extensions';
import { isUserHasCapability, KNOWLEDGE_ORGANIZATION_RESTRICT } from '../../utils/access';
import { FilterMode } from '../../generated/graphql';
import { INPUT_CREATED_BY, INPUT_MARKINGS } from '../../schema/general';
import { addLabel } from '../../domain/label';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import {
  ATTRIBUTE_HUNT_SOURCES,
  ATTRIBUTE_HUNT_TARGETS,
  ATTRIBUTE_HUNT_TECHNIQUES,
  ENTITY_TYPE_HUNT,
  HUNT_SOURCE_HUB,
  HUNT_STATUS_DRAFT,
  INPUT_HUNT_SOURCES,
  INPUT_HUNT_TARGETS,
  INPUT_HUNT_TECHNIQUES,
  type StixHunt,
  type StoreEntityHunt,
} from './hunt-types';

export const HUNT_PACK_MAX_HUNTS = 200;
// Far above a pack of the maximum number of hunts with their references; the upload is refused as soon as it is larger
export const HUNT_PACK_MAX_BYTES = 20 * 1024 * 1024;
const HUNT_STIX_TYPES = ['hunt', 'x-opencti-hunt'];
const HUNT_EXTENSION_CREATED = '2026-10-03T00:00:00.000Z';
// The JSON Schema of the hunt SDO, kept in this repository at config/schema/hunt-extension.json
export const HUNT_EXTENSION_SCHEMA_URL = 'https://raw.githubusercontent.com/OpenCTI-Platform/opencti/master/opencti-platform/opencti-graphql/config/schema/hunt-extension.json';
const FILIGRAN_NAME = 'Filigran';

const filigranIdentityId = () => generateStandardId(ENTITY_TYPE_IDENTITY_ORGANIZATION, { name: FILIGRAN_NAME, identity_class: 'organization' });

// The extension definition of the hunt SDO, so that hunt packs are self-describing STIX 2.1 bundles
export const huntExtensionDefinition = () => ({
  type: 'extension-definition',
  spec_version: STIX_SPEC_VERSION,
  id: STIX_EXT_OCTI_HUNT,
  created_by_ref: filigranIdentityId(),
  created: HUNT_EXTENSION_CREATED,
  modified: HUNT_EXTENSION_CREATED,
  name: 'OpenCTI Hunt',
  description: 'A threat hunt: a falsifiable hypothesis, a canonical Sigma rule with per-platform native queries, the threats and techniques it targets and its execution guardrails.',
  schema: HUNT_EXTENSION_SCHEMA_URL,
  version: '1.0.0',
  extension_types: ['new-sdo'],
});

const filigranIdentity = () => ({
  type: 'identity',
  spec_version: STIX_SPEC_VERSION,
  id: filigranIdentityId(),
  created: HUNT_EXTENSION_CREATED,
  modified: HUNT_EXTENSION_CREATED,
  name: FILIGRAN_NAME,
  identity_class: 'organization',
});

/**
 * A hunt as distributed in a pack: imported hunts always land in draft status with the hub origin, and the
 * platform-specific execution settings (scope over local security platforms, trigger filters) are removed.
 */
export const toPackHunt = (stixHunt: StixHunt): StixHunt => ({
  ...stixHunt,
  hunt_status: HUNT_STATUS_DRAFT,
  hunt_source_kind: HUNT_SOURCE_HUB,
  hunt_scope: '',
  trigger_filters: '',
  hunt_pir_activation: false,
});

/**
 * Hunt pack: STIX 2.1 bundle of hunts with the techniques, threats, indicators, markings and authors they reference.
 * Reports referenced as sources are not distributed (their content is not part of the hunt).
 */
export const exportHuntPack = async (context: AuthContext, user: AuthUser, ids: string[]): Promise<string> => {
  if (ids.length === 0) {
    throw FunctionalError('A hunt pack needs at least one hunt');
  }
  if (ids.length > HUNT_PACK_MAX_HUNTS) {
    throw FunctionalError(`A hunt pack is limited to ${HUNT_PACK_MAX_HUNTS} hunts`, { count: ids.length });
  }
  const objects = new Map<string, unknown>();
  const extension = huntExtensionDefinition();
  objects.set(extension.id, extension);
  const filigran = filigranIdentity();
  objects.set(filigran.id, filigran);
  for (let index = 0; index < ids.length; index += 1) {
    const hunt = await storeLoadByIdWithRefs<StoreEntityHunt>(context, user, ids[index], { type: ENTITY_TYPE_HUNT });
    if (!hunt) {
      throw FunctionalError('Hunt cannot be found or is not accessible', { id: ids[index] });
    }
    const references: StoreEntity[] = [
      ...((hunt[INPUT_HUNT_TECHNIQUES] ?? []) as StoreEntity[]),
      ...((hunt[INPUT_HUNT_TARGETS] ?? []) as StoreEntity[]),
      ...((hunt[INPUT_HUNT_SOURCES] ?? []) as StoreEntity[]).filter((source) => source.entity_type === ENTITY_TYPE_INDICATOR),
    ];
    const stixHunt = toPackHunt(convertStoreToStix_2_1(hunt) as StixHunt);
    const distributedRefs = new Set<string>(references.map((reference) => reference.standard_id));
    stixHunt[ATTRIBUTE_HUNT_SOURCES] = (stixHunt[ATTRIBUTE_HUNT_SOURCES] ?? []).filter((ref) => distributedRefs.has(ref));
    objects.set(stixHunt.id, stixHunt);
    const fullReferences = references.length > 0
      ? await Promise.all(references.map((reference) => storeLoadByIdWithRefs<StoreEntity>(context, user, reference.internal_id)))
      : [];
    const metas: StoreEntity[] = [...((hunt[INPUT_MARKINGS] ?? []) as unknown as StoreEntity[])];
    if (hunt[INPUT_CREATED_BY]) {
      metas.push(hunt[INPUT_CREATED_BY] as unknown as StoreEntity);
    }
    fullReferences.filter((reference): reference is StoreEntity => !!reference).forEach((reference) => {
      objects.set(reference.standard_id, convertStoreToStix_2_1(reference));
      metas.push(...((reference[INPUT_MARKINGS] ?? []) as unknown as StoreEntity[]));
      if (reference[INPUT_CREATED_BY]) {
        metas.push(reference[INPUT_CREATED_BY] as unknown as StoreEntity);
      }
    });
    metas.forEach((meta) => {
      if (!objects.has(meta.standard_id)) {
        objects.set(meta.standard_id, convertStoreToStix_2_1(meta));
      }
    });
  }
  return JSON.stringify({ type: 'bundle', id: `bundle--${uuidv4()}`, objects: Array.from(objects.values()) });
};

export const huntStixBundle = async (context: AuthContext, user: AuthUser, id: string) => exportHuntPack(context, user, [id]);

const MITRE_SOURCE_NAMES = ['mitre-attack', 'mitre-mobile-attack', 'mitre-ics-attack', 'mitre-pre-attack'];
const attackExternalId = (stixObject: Record<string, any> | undefined): string | null => {
  if (!stixObject) {
    return null;
  }
  if (typeof stixObject.x_mitre_id === 'string') {
    return stixObject.x_mitre_id;
  }
  const reference = (stixObject.external_references ?? []).find((ref: { source_name?: string; external_id?: string }) => MITRE_SOURCE_NAMES.includes(ref.source_name ?? ''));
  return reference?.external_id ?? null;
};

/** Creates the missing labels of a pack hunt: only called once the hunt is known to be imported. */
export const resolveHuntPackLabels = async (context: AuthContext, user: AuthUser, labels: string[]) => {
  const values = Array.from(new Set(labels.filter((label) => typeof label === 'string' && label.trim().length > 0)));
  const resolved = await Promise.all(values.map((value) => addLabel(context, user, { value })));
  return resolved.map((label: BasicStoreEntity) => label.internal_id);
};

export interface HuntPackImportPlan {
  input: Record<string, unknown>;
  // Label values, created by resolveHuntPackLabels once the hunt passed every check
  labels: string[];
  unresolved: string[];
  blocked: boolean;
}

/**
 * Builds the creation input of a pack hunt: references are resolved against the local knowledge (standard ids,
 * ATT&CK ids for techniques). A hunt whose markings or organizations cannot be resolved is not imported: importing it
 * without them would lower its protection.
 */
export const planHuntPackImport = async (
  context: AuthContext,
  user: AuthUser,
  stixHunt: StixHunt,
  bundleObjects: Map<string, Record<string, any>>,
): Promise<HuntPackImportPlan> => {
  const unresolved: string[] = [];
  // A reference of the pack names an element by its standard id or by one of its other STIX ids
  const knownIds = (elements: BasicStoreEntity[]) => new Set<string>(elements.flatMap((element) => [element.standard_id, ...(element.x_opencti_stix_ids ?? [])]));
  const resolveIds = async (refs: string[] | undefined) => {
    if (!refs || refs.length === 0) {
      return [];
    }
    const found = await findByIds<BasicStoreEntity>(context, user, refs);
    const foundIds = knownIds(found);
    refs.filter((ref) => !foundIds.has(ref)).forEach((ref) => unresolved.push(ref));
    return found.map((element) => element.internal_id);
  };
  const resolveTechniques = async (refs: string[] | undefined) => {
    if (!refs || refs.length === 0) {
      return [];
    }
    const found = await findByIds<BasicStoreEntity>(context, user, refs, { type: ENTITY_TYPE_ATTACK_PATTERN });
    const foundIds = knownIds(found);
    const missing = refs.filter((ref) => !foundIds.has(ref));
    const byMitreId = missing
      .map((ref) => ({ ref, mitreId: attackExternalId(bundleObjects.get(ref)) }))
      .filter((item): item is { ref: string; mitreId: string } => !!item.mitreId);
    const resolvedByMitre = byMitreId.length > 0
      ? await fullEntitiesList<BasicStoreEntity & { x_mitre_id?: string }>(context, user, [ENTITY_TYPE_ATTACK_PATTERN], {
          filters: { mode: FilterMode.And, filters: [{ key: ['x_mitre_id'], values: byMitreId.map((item) => item.mitreId) }], filterGroups: [] },
        })
      : [];
    const resolvedMitreIds = new Set(resolvedByMitre.map((element) => element.x_mitre_id));
    missing.filter((ref) => !byMitreId.some((item) => item.ref === ref && resolvedMitreIds.has(item.mitreId))).forEach((ref) => unresolved.push(ref));
    return Array.from(new Set([...found.map((element) => element.internal_id), ...resolvedByMitre.map((element) => element.internal_id)]));
  };
  const markingRefs = Array.from(new Set(stixHunt.object_marking_refs ?? []));
  const markings = markingRefs.length > 0 ? await findByIds<BasicStoreEntity>(context, user, markingRefs) : [];
  const foundMarkings = knownIds(markings);
  const missingMarkings = markingRefs.filter((ref) => !foundMarkings.has(ref));
  missingMarkings.forEach((ref) => unresolved.push(ref));
  const markingsBlocked = missingMarkings.length > 0;
  const grantedRefs: unknown = stixHunt.extensions?.[STIX_EXT_OCTI]?.granted_refs;
  const organizationRefs = Array.isArray(grantedRefs) ? Array.from(new Set(grantedRefs.filter((ref): ref is string => typeof ref === 'string'))) : [];
  const organizations = organizationRefs.length > 0
    ? await findByIds<BasicStoreEntity>(context, user, organizationRefs, { type: ENTITY_TYPE_IDENTITY_ORGANIZATION })
    : [];
  const foundOrganizations = knownIds(organizations);
  const missingOrganizations = organizationRefs.filter((ref) => !foundOrganizations.has(ref));
  missingOrganizations.forEach((ref) => unresolved.push(ref));
  const blocked = markingsBlocked || missingOrganizations.length > 0;
  // Without this capability the organizations of a created object are those of its creator, not the ones given
  if (!blocked && organizations.length > 0 && !isUserHasCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT)) {
    throw FunctionalError('This hunt pack holds a hunt restricted to organizations: only a user who can restrict access to organizations can import it', { hunt: stixHunt.id });
  }
  const authorRef = stixHunt.created_by_ref;
  const author = authorRef ? await findByIds<BasicStoreEntity>(context, user, [authorRef]) : [];
  const input: Record<string, unknown> = {
    stix_id: stixHunt.id,
    name: stixHunt.name,
    description: stixHunt.description,
    hypothesis: stixHunt.hypothesis,
    hunt_type: stixHunt.hunt_type,
    hunt_status: HUNT_STATUS_DRAFT,
    hunt_source_kind: HUNT_SOURCE_HUB,
    sigma_rule: stixHunt.sigma_rule,
    native_queries: stixHunt.native_queries ?? [],
    hunt_ioc_filters: stixHunt.hunt_ioc_filters || undefined,
    hunt_ioc_values: stixHunt.hunt_ioc_values ?? [],
    hunt_schedule: stixHunt.hunt_schedule,
    time_window_hours: stixHunt.time_window_hours,
    expected_observables: stixHunt.expected_observables ?? [],
    benign_patterns: stixHunt.benign_patterns ?? [],
    escalation_threshold: stixHunt.escalation_threshold,
    escalate_manual_runs: stixHunt.escalate_manual_runs === true,
    hunt_max_results: stixHunt.hunt_max_results || undefined,
    [INPUT_HUNT_TECHNIQUES]: await resolveTechniques(stixHunt[ATTRIBUTE_HUNT_TECHNIQUES]),
    [INPUT_HUNT_TARGETS]: await resolveIds(stixHunt[ATTRIBUTE_HUNT_TARGETS]),
    [INPUT_HUNT_SOURCES]: await resolveIds(stixHunt[ATTRIBUTE_HUNT_SOURCES]),
    objectMarking: markings.map((marking) => marking.internal_id),
  };
  if (organizations.length > 0) {
    input.objectOrganization = organizations.map((organization) => organization.internal_id);
  }
  if (author.length > 0) {
    input.createdBy = author[0].internal_id;
  }
  return { input, labels: stixHunt.labels ?? [], unresolved, blocked };
};

// The upload is read under the byte limit: an oversized file is refused while it streams, never buffered in full
const readHuntPackFile = async (file: Promise<FileHandle>): Promise<string> => {
  const upload = await file;
  const stream = upload.createReadStream();
  return new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    stream.on('data', (chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buffer.length;
      if (size > HUNT_PACK_MAX_BYTES) {
        stream.destroy();
        reject(FunctionalError(`A hunt pack is limited to ${HUNT_PACK_MAX_BYTES / (1024 * 1024)} MB`, { limit: HUNT_PACK_MAX_BYTES }));
        return;
      }
      chunks.push(buffer);
    });
    stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    stream.on('error', reject);
  });
};

export const parseHuntPack = async (file: Promise<FileHandle>) => {
  const content = await readHuntPackFile(file);
  let bundle: { type?: string; objects?: Record<string, any>[] } | null;
  try {
    bundle = JSON.parse(content);
  } catch {
    throw FunctionalError('A hunt pack must be a STIX 2.1 bundle');
  }
  if (bundle?.type !== 'bundle' || !Array.isArray(bundle.objects)) {
    throw FunctionalError('A hunt pack must be a STIX 2.1 bundle');
  }
  const objects = new Map<string, Record<string, any>>(bundle.objects.filter((object) => typeof object?.id === 'string').map((object) => [object.id, object]));
  // A hunt listed twice is imported once, as its last occurrence (like every other object of the bundle)
  const hunts = Array.from(new Map((bundle.objects.filter((object) => HUNT_STIX_TYPES.includes(object?.type)) as StixHunt[])
    .map((hunt) => [hunt.id, hunt])).values());
  if (hunts.length === 0) {
    throw FunctionalError('The bundle does not contain any hunt');
  }
  if (hunts.length > HUNT_PACK_MAX_HUNTS) {
    throw FunctionalError(`A hunt pack is limited to ${HUNT_PACK_MAX_HUNTS} hunts`, { count: hunts.length });
  }
  return { hunts, objects: objects as Map<string, Record<string, any>> & Map<string, StixObject> };
};
