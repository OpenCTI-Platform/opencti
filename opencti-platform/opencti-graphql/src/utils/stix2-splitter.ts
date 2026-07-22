// Node.js port of client-python's OpenCTIStix2Splitter (pycti/utils/opencti_stix2_splitter.py).
// This is an isolated, standalone port (Proposal B POC step 1): it duplicates pycti's
// behavior on purpose, including its static supported-type list, so the two implementations
// can be validated against the same golden fixtures before anything is wired to a call site.
import { v4 as uuidv4, v5 as uuidv5 } from 'uuid';
import jsonCanonicalize from 'canonicalize';
import { OASIS_NAMESPACE } from '../schema/general';

// Mirrors pycti's SUPPORTED_INTERNAL_OBJECTS (opencti_stix2_utils.py)
const SUPPORTED_INTERNAL_OBJECTS = [
  'user',
  'group',
  'capability',
  'role',
  'settings',
  'notification',
  'work',
  'trash',
  'draftworkspace',
  'playbook',
  'deleteoperation',
  'workspace',
  'publicdashboard',
];

// Mirrors pycti's STIX_META_OBJECTS + STIX_CORE_OBJECTS (opencti_stix2_utils.py)
const SUPPORTED_STIX_ENTITY_OBJECTS = [
  // Meta objects
  'label',
  'vocabulary',
  'kill-chain-phase',
  // Core objects
  'attack-pattern',
  'campaign',
  'case-incident',
  'x-opencti-case-incident',
  'case-rfi',
  'x-opencti-case-rfi',
  'case-rft',
  'x-opencti-case-rft',
  'channel',
  'course-of-action',
  'data-component',
  'x-mitre-data-component',
  'data-source',
  'x-mitre-data-source',
  'event',
  'external-reference',
  'feedback',
  'x-opencti-feedback',
  'grouping',
  'identity',
  'incident',
  'indicator',
  'infrastructure',
  'intrusion-set',
  'language',
  'location',
  'malware',
  'malware-analysis',
  'marking-definition',
  'narrative',
  'note',
  'observed-data',
  'opinion',
  'report',
  'task',
  'x-opencti-task',
  'threat-actor',
  'tool',
  'vulnerability',
  'security-coverage',
];

// Mirrors pycti's STIX_CYBER_OBSERVABLE_MAPPING keys (opencti_stix2_utils.py)
const STIX_CYBER_OBSERVABLE_TYPES = [
  'autonomous-system',
  'directory',
  'domain-name',
  'email-addr',
  'email-message',
  'email-mime-part-type',
  'artifact',
  'file',
  'x509-certificate',
  'ipv4-addr',
  'ipv6-addr',
  'mac-addr',
  'mutex',
  'network-traffic',
  'process',
  'software',
  'url',
  'user-account',
  'windows-registry-key',
  'windows-registry-value-type',
  'hostname',
  'cryptographic-key',
  'cryptocurrency-wallet',
  'text',
  'user-agent',
  'bank-account',
  'phone-number',
  'credential',
  'tracking-number',
  'payment-card',
  'media-content',
  'simple-observable',
  'persona',
  'ssh-key',
  'ai-prompt',
  'imei',
  'iccid',
  'imsi',
];

const SUPPORTED_TYPES = new Set([
  ...SUPPORTED_STIX_ENTITY_OBJECTS,
  ...SUPPORTED_INTERNAL_OBJECTS,
  ...STIX_CYBER_OBSERVABLE_TYPES,
  'relationship',
  'sighting',
  'pir',
]);

// Mirrors pycti's is_id_supported (opencti_stix2_splitter.py)
export const isIdSupported = (key: string): boolean => {
  if (key.includes('--')) {
    const idType = key.split('--')[0];
    return SUPPORTED_TYPES.has(idType);
  }
  // If not a stix id, don't try to filter
  return true;
};

// Mirrors pycti's external_reference_generate_id (opencti_stix2_identifier.py)
export const externalReferenceGenerateId = (opts: { url?: string | null; sourceName?: string | null; externalId?: string | null }): string | null => {
  const { url, sourceName, externalId } = opts;
  let data: Record<string, string>;
  if (url) {
    data = { url };
  } else if (sourceName && externalId) {
    data = { source_name: sourceName, external_id: externalId };
  } else {
    return null;
  }
  const canonicalData = jsonCanonicalize(data) as string;
  return `external-reference--${uuidv5(canonicalData, OASIS_NAMESPACE)}`;
};

// Mirrors pycti's kill_chain_phase_generate_id (opencti_stix2_identifier.py)
export const killChainPhaseGenerateId = (opts: { phaseName: string; killChainName: string }): string => {
  const { phaseName, killChainName } = opts;
  const data = { phase_name: phaseName, kill_chain_name: killChainName };
  const canonicalData = jsonCanonicalize(data) as string;
  return `kill-chain-phase--${uuidv5(canonicalData, OASIS_NAMESPACE)}`;
};

type StixObject = Record<string, any>;

interface SplitResult {
  numberExpectations: number;
  incompatibleItems: StixObject[];
  bundles: string[] | StixObject[];
}

// Mirrors pycti's OpenCTIStix2Splitter (opencti_stix2_splitter.py)
export class Stix2Splitter {
  private cacheIndex: Map<string, StixObject> = new Map();

  private cacheRefs: Map<string, string[]> = new Map();

  private elements: StixObject[] = [];

  private incompatibleItems: StixObject[] = [];

  // Mirrors get_internal_ids_in_extension
  private getInternalIdsInExtension(item: StixObject): string[] {
    const ids: string[] = [];
    if (item.x_opencti_id) {
      ids.push(item.x_opencti_id);
    }
    const openctiExtension = item.extensions?.['extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba'];
    if (openctiExtension?.id) {
      ids.push(openctiExtension.id);
    }
    return ids;
  }

  // Mirrors enlist_element
  private enlistElement(itemId: string, rawData: Map<string, StixObject>, cleanupInconsistentBundle: boolean, parentAcc: string[]): number {
    let nbDeps = 1;
    if (!rawData.has(itemId)) {
      return 0;
    }

    const existingItem = this.cacheIndex.get(itemId);
    if (existingItem !== undefined) {
      return existingItem.nb_deps;
    }

    const item = rawData.get(itemId) as StixObject;
    if (!this.cacheRefs.has(itemId)) {
      this.cacheRefs.set(itemId, []);
    }
    for (const key of Object.keys(item)) {
      const value = item[key];
      if (key.endsWith('_refs') && value !== null && value !== undefined) {
        const toKeep: string[] = [];
        for (const elementRef of value as string[]) {
          const isMissingRef = !rawData.has(elementRef);
          const mustBeCleaned = isMissingRef && cleanupInconsistentBundle;
          const itemRefs = this.cacheRefs.get(elementRef);
          const notDependencyRef = itemRefs === undefined || !itemRefs.includes(itemId);
          if (isIdSupported(elementRef) && !mustBeCleaned && !parentAcc.includes(elementRef) && elementRef !== itemId && notDependencyRef) {
            (this.cacheRefs.get(itemId) as string[]).push(elementRef);
            nbDeps += this.enlistElement(elementRef, rawData, cleanupInconsistentBundle, [...parentAcc, elementRef]);
            if (!toKeep.includes(elementRef)) {
              toKeep.push(elementRef);
            }
          }
        }
        item[key] = toKeep;
      } else if (key.endsWith('_ref')) {
        const isMissingRef = value !== null && value !== undefined && !rawData.has(value);
        const mustBeCleaned = isMissingRef && cleanupInconsistentBundle;
        const itemRefs = this.cacheRefs.get(value);
        const notDependencyRef = itemRefs === undefined || !itemRefs.includes(itemId);
        if (value !== null && value !== undefined && !mustBeCleaned && !parentAcc.includes(value) && isIdSupported(value) && value !== itemId && notDependencyRef) {
          (this.cacheRefs.get(itemId) as string[]).push(value);
          nbDeps += this.enlistElement(value, rawData, cleanupInconsistentBundle, [...parentAcc, value]);
        } else {
          item[key] = null;
        }
      } else if (key === 'external_references' && value !== null && value !== undefined) {
        const deduplicatedReferences: StixObject[] = [];
        const deduplicatedReferencesCache = new Set<string>();
        for (const reference of value as StixObject[]) {
          const referenceId = externalReferenceGenerateId({ url: reference.url, sourceName: reference.source_name, externalId: reference.external_id });
          if (referenceId !== null && !deduplicatedReferencesCache.has(referenceId)) {
            deduplicatedReferencesCache.add(referenceId);
            deduplicatedReferences.push(reference);
          }
        }
        item[key] = deduplicatedReferences;
      } else if (key === 'kill_chain_phases' && value !== null && value !== undefined) {
        const deduplicatedKillChain: StixObject[] = [];
        const deduplicatedKillChainCache = new Set<string>();
        for (const killChain of value as StixObject[]) {
          const killChainId = killChainPhaseGenerateId({ phaseName: killChain.phase_name, killChainName: killChain.kill_chain_name });
          if (!deduplicatedKillChainCache.has(killChainId)) {
            deduplicatedKillChainCache.add(killChainId);
            deduplicatedKillChain.push(killChain);
          }
        }
        item[key] = deduplicatedKillChain;
      }
    }

    // Get the final dep counting and add in cache
    item.nb_deps = nbDeps;
    // Put in cache
    if (!this.cacheIndex.has(itemId)) {
      let isCompatible: boolean;
      if (item.type === 'relationship') {
        isCompatible = item.source_ref !== null && item.source_ref !== undefined && item.target_ref !== null && item.target_ref !== undefined;
      } else if (item.type === 'sighting') {
        isCompatible = !!item.sighting_of_ref && (item.where_sighted_refs?.length ?? 0) > 0;
      } else {
        isCompatible = isIdSupported(itemId);
      }

      if (isCompatible) {
        this.elements.push(item);
      } else {
        this.incompatibleItems.push(item);
      }
      this.cacheIndex.set(itemId, item);
      for (const internalId of this.getInternalIdsInExtension(item)) {
        this.cacheIndex.set(internalId, item);
      }
    }

    return nbDeps;
  }

  // Mirrors stix2_create_bundle
  static stix2CreateBundle(bundleId: string, bundleSeq: number, items: StixObject[], useJson: boolean, eventVersion?: string | null): string | StixObject {
    const bundle: StixObject = {
      type: 'bundle',
      id: bundleId,
      spec_version: '2.1',
      x_opencti_seq: bundleSeq,
      objects: items,
    };
    if (eventVersion !== undefined && eventVersion !== null) {
      bundle.x_opencti_event_version = eventVersion;
    }
    return useJson ? JSON.stringify(bundle) : bundle;
  }

  // Mirrors split_bundle_with_expectations
  splitBundleWithExpectations(bundle: string | StixObject, useJson = true, eventVersion?: string | null, cleanupInconsistentBundle = false): SplitResult {
    let bundleData: StixObject;
    if (useJson) {
      try {
        bundleData = JSON.parse(bundle as string);
      } catch (e) {
        throw new Error('File data is not a valid JSON', { cause: e });
      }
    } else {
      bundleData = bundle as StixObject;
    }

    if (!('objects' in bundleData)) {
      throw new Error('File data is not a valid bundle');
    }
    if (!('id' in bundleData)) {
      bundleData.id = `bundle--${uuidv4()}`;
    }

    const rawData = new Map<string, StixObject>();

    // Build flat list of elements
    for (const item of bundleData.objects as StixObject[]) {
      rawData.set(item.id, item);
      for (const internalId of this.getInternalIdsInExtension(item)) {
        rawData.set(internalId, item);
      }
    }
    for (const item of bundleData.objects as StixObject[]) {
      this.enlistElement(item.id, rawData, cleanupInconsistentBundle, []);
    }

    // Build the bundles: sort by dependency weight, one object per resulting bundle
    this.elements.sort((a, b) => a.nb_deps - b.nb_deps);

    const bundles: (string | StixObject)[] = [];
    let numberExpectations = 0;
    for (const entity of this.elements) {
      numberExpectations += 1;
      bundles.push(Stix2Splitter.stix2CreateBundle(bundleData.id, entity.nb_deps, [entity], useJson, eventVersion));
    }

    return {
      numberExpectations,
      incompatibleItems: this.incompatibleItems,
      bundles: bundles as string[] | StixObject[],
    };
  }
}
