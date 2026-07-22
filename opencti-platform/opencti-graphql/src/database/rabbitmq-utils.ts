import { v4 as uuidv4, v5 as uuidv5 } from 'uuid';
import jsonCanonicalize from 'canonicalize';

// Namespace used by OpenCTI to generate deterministic STIX ids (mirrors OASIS_NAMESPACE).
const OASIS_NAMESPACE = '00abedb4-aa42-466c-9c01-fed23315a9b7';

const OPENCTI_EXTENSION = 'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba';

// region supported types (mirror of pycti opencti_stix2_utils)
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

const STIX_META_OBJECTS = [
  'label',
  'vocabulary',
  'kill-chain-phase',
];

const STIX_CORE_OBJECTS = [
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

const SUPPORTED_STIX_ENTITY_OBJECTS = [...STIX_META_OBJECTS, ...STIX_CORE_OBJECTS];

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

const SUPPORTED_TYPES = [
  ...SUPPORTED_STIX_ENTITY_OBJECTS, // entities
  ...SUPPORTED_INTERNAL_OBJECTS, // internals
  ...STIX_CYBER_OBSERVABLE_TYPES, // observables
  'relationship',
  'sighting', // relationships
  'pir',
];
// endregion

/**
 * Check if a STIX ID type is supported for processing.
 */
export const isIdSupported = (key: string): boolean => {
  if (key.includes('--')) {
    const idType = key.split('--')[0];
    return SUPPORTED_TYPES.includes(idType);
  }
  // If not a stix id, don't try to filter
  return true;
};

/**
 * Generate a STIX ID for an external reference.
 */
export const externalReferenceGenerateId = (
  { url, sourceName, externalId }: { url?: string; sourceName?: string; externalId?: string },
): string | null => {
  let data: Record<string, string>;
  if (url !== undefined && url !== null) {
    data = { url };
  } else if (sourceName !== undefined && sourceName !== null && externalId !== undefined && externalId !== null) {
    data = { source_name: sourceName, external_id: externalId };
  } else {
    return null;
  }
  const canonical = jsonCanonicalize(data) as string;
  return `external-reference--${uuidv5(canonical, OASIS_NAMESPACE)}`;
};

/**
 * Generate a STIX ID for a kill chain phase.
 */
export const killChainPhaseGenerateId = (
  { phaseName, killChainName }: { phaseName?: string; killChainName?: string },
): string => {
  const data = { phase_name: phaseName, kill_chain_name: killChainName };
  const canonical = jsonCanonicalize(data) as string;
  return `kill-chain-phase--${uuidv5(canonical, OASIS_NAMESPACE)}`;
};

type StixItem = Record<string, any>;

export interface StixBundle {
  type: string;
  id: string;
  spec_version?: string;
  x_opencti_seq?: number;
  x_opencti_event_version?: string;
  objects: StixItem[];
}

export type SplitBundleResult = {
  expectations: number;
  incompatibleItems: StixItem[];
  bundles: (string | StixBundle)[];
};

/**
 * STIX2 bundle splitter for OpenCTI.
 *
 * Splits large STIX2 bundles into smaller chunks for processing,
 * handling dependencies between objects and deduplicating references.
 *
 * TypeScript translation of pycti.utils.opencti_stix2_splitter.OpenCTIStix2Splitter.
 */
export class OpenCTIStix2Splitter {
  private cacheIndex: Record<string, StixItem> = {};

  private cacheRefs: Record<string, string[]> = {};

  private elements: StixItem[] = [];

  private incompatibleItems: StixItem[] = [];

  /**
   * Get internal IDs from OpenCTI extensions in a STIX object.
   */
  private getInternalIdsInExtension(item: StixItem): string[] {
    const ids: string[] = [];
    if (item.x_opencti_id) {
      ids.push(item.x_opencti_id);
    }
    const extension = item.extensions?.[OPENCTI_EXTENSION];
    if (extension?.id) {
      ids.push(extension.id);
    }
    return ids;
  }

  /**
   * Enlist an element and its dependencies for processing.
   */
  private enlistElement(
    itemId: string,
    rawData: Record<string, StixItem>,
    cleanupInconsistentBundle: boolean,
    parentAcc: string[],
  ): number {
    let nbDeps = 1;
    if (!(itemId in rawData)) {
      return 0;
    }

    const existingItem = this.cacheIndex[itemId];
    if (existingItem !== undefined) {
      return existingItem.nb_deps;
    }

    const item = rawData[itemId];
    if (this.cacheRefs[itemId] === undefined) {
      this.cacheRefs[itemId] = [];
    }
    for (const key of Object.keys(item)) {
      const value = item[key];
      // Recursive enlist for every refs
      if (key.endsWith('_refs') && item[key] !== null && item[key] !== undefined) {
        const toKeep: string[] = [];
        for (const elementRef of item[key]) {
          // We need to check if this ref is not already a reference
          const isMissingRef = rawData[elementRef] === undefined;
          const mustBeCleaned = isMissingRef && cleanupInconsistentBundle;
          const notDependencyRef = this.cacheRefs[elementRef] === undefined
            || !this.cacheRefs[elementRef].includes(itemId);
          // Prevent any self reference
          if (
            isIdSupported(elementRef)
            && !mustBeCleaned
            && !parentAcc.includes(elementRef)
            && elementRef !== itemId
            && notDependencyRef
          ) {
            this.cacheRefs[itemId].push(elementRef);
            nbDeps += this.enlistElement(
              elementRef,
              rawData,
              cleanupInconsistentBundle,
              [...parentAcc, elementRef],
            );
            if (!toKeep.includes(elementRef)) {
              toKeep.push(elementRef);
            }
          }
          item[key] = toKeep;
        }
      } else if (key.endsWith('_ref')) {
        const isMissingRef = rawData[value] === undefined;
        const mustBeCleaned = isMissingRef && cleanupInconsistentBundle;
        const notDependencyRef = this.cacheRefs[value] === undefined
          || !this.cacheRefs[value].includes(itemId);
        // Prevent any self reference
        if (
          value !== null
          && value !== undefined
          && !mustBeCleaned
          && !parentAcc.includes(value)
          && isIdSupported(value)
          && value !== itemId
          && notDependencyRef
        ) {
          this.cacheRefs[itemId].push(value);
          nbDeps += this.enlistElement(
            value,
            rawData,
            cleanupInconsistentBundle,
            [...parentAcc, value],
          );
        } else {
          item[key] = null;
        }
      } else if (key === 'external_references' && item[key] !== null && item[key] !== undefined) {
        // specific case of splitting external references (deduplicating and cleanup)
        const deduplicatedReferences: StixItem[] = [];
        const deduplicatedReferencesCache: Record<string, string> = {};
        for (const reference of item[key]) {
          const referenceId = externalReferenceGenerateId({
            url: reference.url,
            sourceName: reference.source_name,
            externalId: reference.external_id,
          });
          if (referenceId !== null && deduplicatedReferencesCache[referenceId] === undefined) {
            deduplicatedReferencesCache[referenceId] = referenceId;
            deduplicatedReferences.push(reference);
          }
        }
        item[key] = deduplicatedReferences;
      } else if (key === 'kill_chain_phases' && item[key] !== null && item[key] !== undefined) {
        // specific case of splitting kill_chain phases (deduplicating and cleanup)
        const deduplicatedKillChain: StixItem[] = [];
        const deduplicatedKillChainCache: Record<string, string> = {};
        for (const killChain of item[key]) {
          const killChainId = killChainPhaseGenerateId({
            killChainName: killChain.kill_chain_name,
            phaseName: killChain.phase_name,
          });
          if (deduplicatedKillChainCache[killChainId] === undefined) {
            deduplicatedKillChainCache[killChainId] = killChainId;
            deduplicatedKillChain.push(killChain);
          }
        }
        item[key] = deduplicatedKillChain;
      }
    }

    // Get the final dep counting and add in cache
    item.nb_deps = nbDeps;
    // Put in cache
    if (this.cacheIndex[itemId] === undefined) {
      let isCompatible: boolean;
      // enlist only if compatible
      if (item.type === 'relationship') {
        isCompatible = item.source_ref !== null && item.source_ref !== undefined
          && item.target_ref !== null && item.target_ref !== undefined;
      } else if (item.type === 'sighting') {
        isCompatible = item.sighting_of_ref !== null && item.sighting_of_ref !== undefined
          && (item.where_sighted_refs ?? []).length > 0;
      } else {
        isCompatible = isIdSupported(itemId);
      }

      if (isCompatible) {
        this.elements.push(item);
      } else {
        this.incompatibleItems.push(item);
      }
      this.cacheIndex[itemId] = item;
      for (const internalId of this.getInternalIdsInExtension(item)) {
        this.cacheIndex[internalId] = item;
      }
    }

    return nbDeps;
  }

  /**
   * Split a valid STIX2 bundle into a list of bundles.
   *
   * @param bundle the STIX2 bundle to split (JSON string or object)
   * @param useJson whether to return bundles as JSON string (true) or object (false)
   * @param eventVersion optional event version to include in bundles
   * @param cleanupInconsistentBundle whether to cleanup inconsistent references
   * @returns the number of expectations, the incompatible items and the list of bundles
   */
  public splitBundleWithExpectations(
    bundle: string | StixBundle,
    useJson: boolean = true,
    eventVersion?: string,
    cleanupInconsistentBundle: boolean = false,
  ): SplitBundleResult {
    // Reset internal state to allow reusing the same splitter instance safely
    this.cacheIndex = {};
    this.cacheRefs = {};
    this.elements = [];
    this.incompatibleItems = [];
    const bundleData: StixBundle = typeof bundle === 'string' ? JSON.parse(bundle) : bundle;
    if (!('objects' in bundleData)) {
      throw new Error('File data is not a valid bundle');
    }
    if (!('id' in bundleData) || bundleData.id === undefined) {
      bundleData.id = `bundle--${uuidv4()}`;
    }

    const rawData: Record<string, StixItem> = {};

    // Build flat list of elements
    for (const item of bundleData.objects) {
      rawData[item.id] = item;
      for (const internalId of this.getInternalIdsInExtension(item)) {
        rawData[internalId] = item;
      }
    }
    for (const item of bundleData.objects) {
      this.enlistElement(item.id, rawData, cleanupInconsistentBundle, []);
    }

    // Build the bundles
    const bundles: (string | StixBundle)[] = [];

    this.elements.sort((a, b) => a.nb_deps - b.nb_deps);

    const elementsWithDeps = this.elements.map((e) => ({ nb_deps: e.nb_deps, elements: [e] }));

    let numberExpectations = 0;
    for (const entity of elementsWithDeps) {
      numberExpectations += entity.elements.length;
      bundles.push(
        OpenCTIStix2Splitter.stix2CreateBundle(
          bundleData.id,
          entity.nb_deps,
          entity.elements,
          useJson,
          eventVersion,
        ),
      );
    }

    return {
      expectations: numberExpectations,
      incompatibleItems: this.incompatibleItems,
      bundles,
    };
  }

  /**
   * Create a STIX2 bundle with items.
   */
  public static stix2CreateBundle(
    bundleId: string,
    bundleSeq: number,
    items: StixItem[],
    useJson: boolean,
    eventVersion?: string,
  ): string | StixBundle {
    const bundle: StixBundle = {
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
}
