import { patchAttribute } from '../database/middleware';
import { fullEntitiesList, storeLoadById } from '../database/middleware-loader';
import { completeConnector } from '../database/repository';
import { notify } from '../database/redis';
import { isEmptyField, isNotEmptyField, READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { BUS_TOPICS } from '../config/conf';
import { FunctionalError } from '../config/errors';
import { ConnectorCatalogIdentitySource } from '../generated/graphql';
import { publishUserAction } from '../listener/UserActionListener';
import { type BasicStoreEntityCatalogContract, ENTITY_TYPE_CATALOG_CONTRACT } from '../modules/catalog/catalog-types';
import { selectLatestContractsBySlug } from '../modules/catalog/catalog-version-utils';
import { ABSTRACT_INTERNAL_OBJECT } from '../schema/general';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import type { BasicStoreEntityConnector } from '../types/connector';
import type { AuthContext, AuthUser } from '../types/user';
import { executionContext, SYSTEM_USER } from '../utils/access';

// Identity of a connector in the catalog, resolved for every connector, managed or not.
// Order of trust: the composer contract, a catalog entry chosen by hand, the slug the
// connector reported at registration, then a name matching exactly one catalog entry: equal to
// its title or its slug, otherwise containing its title or contained in it. A wrong logo is worse
// than no logo: an ambiguous name resolves to nothing.

export interface ConnectorCatalogIdentity {
  slug: string;
  title: string;
  logo: string | null;
  short_description: string | null;
  source: ConnectorCatalogIdentitySource;
}

export type CatalogIdentityContract = Pick<BasicStoreEntityCatalogContract, 'slug' | 'title' | 'logo_uri' | 'connector_type' | 'short_description'>;

interface IndexedCatalogContract {
  contract: CatalogIdentityContract;
  // Keys of the title, compared for equality and for containment.
  keys: string[];
  // The slug names the image of the entry (opencti/connector-<slug>) and deployers often name the
  // connector after it: a name equal to the slug designates the entry, a name containing it does not.
  slugKey: string;
  tokens: string[];
}

export interface CatalogIdentityIndex {
  bySlug: Map<string, CatalogIdentityContract>;
  byConnectorType: Map<string, IndexedCatalogContract[]>;
}

type IdentityConnector = Pick<BasicStoreEntityConnector, 'name' | 'connector_type' | 'slug' | 'catalog_slug_manual' | 'built_in' | 'manager_contract' | 'catalog_id'>;

// Same rule as completeConnector (is_managed): a connector deployed by the composer has a catalog_id.
const isManagedConnector = (connector: Pick<IdentityConnector, 'manager_contract' | 'catalog_id'>) => {
  return Boolean(connector.manager_contract) || isNotEmptyField(connector.catalog_id);
};

// Below this length a key or a set of words is part of too many unrelated names ("S3", "MISP", "Spur")
// to identify a connector by containment; equality still applies to short names.
export const MIN_CONTAINMENT_LENGTH = 5;
// Publishers that deployers put in front of a connector name while the catalog title omits them.
const VENDOR_PREFIXES = [/^abuse[\s._-]*ch\b[\s:._|-]*/i];
// Parenthesised or bracketed suffixes: "(KEV)", "(Deprecated)", "[composer]". Only at the end of
// the name: an interior qualifier ("Foo (different) Bar") is part of the identity.
const TRAILING_QUALIFIERS = /(?:\s*(?:\([^)]*\)|\[[^\]]*\]))+\s*$/;
const NOISE_WORDS = /\bconnector\b/gi;
// A name is only compared with the catalog entries of the same connector type; an analysis
// connector runs the image of an import file connector (import-document in analysis mode).
const NAME_MATCH_CATALOG_TYPES: Record<string, string[]> = {
  INTERNAL_ANALYSIS: ['INTERNAL_ANALYSIS', 'INTERNAL_IMPORT_FILE'],
};

const cleanIdentityName = (value: string) => value.replace(TRAILING_QUALIFIERS, ' ').replace(NOISE_WORDS, ' ').trim();

const stripVendorPrefix = (value: string) => VENDOR_PREFIXES.reduce((current, prefix) => current.replace(prefix, ''), value);

// Lower case, accents removed, every character other than a letter or a digit dropped.
export const compactIdentityKey = (value: string) => value
  .normalize('NFKD')
  .replace(/[\u0300-\u036f]/g, '')
  .toLowerCase()
  .replace(/[^a-z0-9]/g, '');

export const identityKeys = (value: string | null | undefined): string[] => {
  if (isEmptyField(value)) {
    return [];
  }
  const cleaned = cleanIdentityName(value as string);
  const keys = new Set([compactIdentityKey(cleaned), compactIdentityKey(stripVendorPrefix(cleaned))]);
  return [...keys].filter((key) => key.length > 1);
};

// Words of a name, camel case and letter/digit boundaries included: "ExportFileStix2" -> export, file, stix, 2.
export const identityTokens = (value: string | null | undefined): string[] => {
  if (isEmptyField(value)) {
    return [];
  }
  return cleanIdentityName(value as string)
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/([a-zA-Z])(\d)/g, '$1 $2')
    .replace(/(\d)([a-zA-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((token) => token.length > 0);
};

const indexContract = (contract: CatalogIdentityContract): IndexedCatalogContract => ({
  contract,
  keys: identityKeys(contract.title),
  slugKey: compactIdentityKey(contract.slug),
  tokens: identityTokens(contract.title),
});

export const buildCatalogIdentityIndex = (contracts: CatalogIdentityContract[]): CatalogIdentityIndex => {
  const bySlug = new Map<string, CatalogIdentityContract>();
  const byConnectorType = new Map<string, IndexedCatalogContract[]>();
  for (const contract of contracts) {
    if (isEmptyField(contract.slug) || isEmptyField(contract.title)) {
      continue;
    }
    const slugKey = contract.slug.toLowerCase();
    if (bySlug.has(slugKey)) {
      continue;
    }
    bySlug.set(slugKey, contract);
    const indexed = byConnectorType.get(contract.connector_type) ?? [];
    indexed.push(indexContract(contract));
    byConnectorType.set(contract.connector_type, indexed);
  }
  return { bySlug, byConnectorType };
};

const isContainedIn = (indexed: IndexedCatalogContract, nameKeys: string[], nameTokens: Set<string>) => {
  const byKey = indexed.keys.some((contractKey) => nameKeys.some((nameKey) => {
    return (contractKey.length >= MIN_CONTAINMENT_LENGTH && nameKey.includes(contractKey))
      || (nameKey.length >= MIN_CONTAINMENT_LENGTH && contractKey.includes(nameKey));
  }));
  if (byKey) {
    return true;
  }
  // Every word of the catalog title is a word of the name: "Abuse.ch SSL Blacklist" contains "Abuse SSL".
  const titleLength = indexed.tokens.reduce((length, token) => length + token.length, 0);
  return titleLength >= MIN_CONTAINMENT_LENGTH && indexed.tokens.every((token) => nameTokens.has(token));
};

// Every catalog entry the name designates: the exact matches when there are any, the containment
// matches otherwise. The caller accepts the result only when it holds exactly one entry.
export const matchCatalogContractsByName = (name: string | null | undefined, candidates: IndexedCatalogContract[]): CatalogIdentityContract[] => {
  const nameKeys = identityKeys(name);
  if (nameKeys.length === 0) {
    return [];
  }
  const exactMatches = candidates.filter((indexed) => nameKeys.includes(indexed.slugKey) || indexed.keys.some((key) => nameKeys.includes(key)));
  if (exactMatches.length > 0) {
    return exactMatches.map((indexed) => indexed.contract);
  }
  const nameTokens = new Set(identityTokens(name));
  return candidates.filter((indexed) => isContainedIn(indexed, nameKeys, nameTokens)).map((indexed) => indexed.contract);
};

export const findCatalogContractByName = (index: CatalogIdentityIndex, name: string | null | undefined, connectorType: string | null | undefined) => {
  const types = NAME_MATCH_CATALOG_TYPES[connectorType ?? ''] ?? [connectorType ?? ''];
  const candidates = types.flatMap((type) => index.byConnectorType.get(type) ?? []);
  const matches = matchCatalogContractsByName(name, candidates);
  return matches.length === 1 ? matches[0] : undefined;
};

const findCatalogContractBySlug = (index: CatalogIdentityIndex, slug: string | null | undefined) => {
  if (isEmptyField(slug)) {
    return undefined;
  }
  return index.bySlug.get((slug as string).trim().toLowerCase());
};

const toIdentity = (contract: CatalogIdentityContract, source: ConnectorCatalogIdentitySource): ConnectorCatalogIdentity => ({
  slug: contract.slug,
  title: contract.title,
  logo: contract.logo_uri || null,
  short_description: contract.short_description || null,
  source,
});

export const resolveConnectorCatalogIdentity = (connector: IdentityConnector, index: CatalogIdentityIndex): ConnectorCatalogIdentity | null => {
  // Built-in connectors (platform internals, feed queues) are not catalog connectors, whatever
  // contract they may carry.
  if (connector.built_in) {
    return null;
  }
  const managerContract = connector.manager_contract;
  if (managerContract) {
    return toIdentity(managerContract, ConnectorCatalogIdentitySource.Composer);
  }
  // A managed connector (catalog_id) takes its identity from its deployment only, even when its
  // contract could not be embedded.
  if (isManagedConnector(connector)) {
    return null;
  }
  const manual = findCatalogContractBySlug(index, connector.catalog_slug_manual);
  if (manual) {
    return toIdentity(manual, ConnectorCatalogIdentitySource.Manual);
  }
  const reported = findCatalogContractBySlug(index, connector.slug);
  if (reported) {
    return toIdentity(reported, ConnectorCatalogIdentitySource.Reported);
  }
  const byName = findCatalogContractByName(index, connector.name, connector.connector_type);
  return byName ? toIdentity(byName, ConnectorCatalogIdentitySource.Name) : null;
};

const IDENTITY_CONTRACT_FIELDS = ['slug', 'title', 'logo_uri', 'connector_type', 'short_description', 'contract_id', 'contract_version', 'support_version', 'min_version', 'max_version'];

// The latest compatible version of each catalog entry, read as the system user because the
// identity only exposes public catalog data (title, logo, slug, short description). The listing
// is shared by every request for a minute: it runs in a context of its own, so the abort signal
// or the draft of the request that started it never reaches the other requests.
const listCatalogIdentityIndex = async () => {
  const context = executionContext('connector_catalog_identity', SYSTEM_USER);
  const contracts = await fullEntitiesList<BasicStoreEntityCatalogContract>(context, SYSTEM_USER, [ENTITY_TYPE_CATALOG_CONTRACT], {
    indices: [READ_INDEX_INTERNAL_OBJECTS],
    baseData: true,
    baseFields: IDENTITY_CONTRACT_FIELDS,
  });
  return buildCatalogIdentityIndex(selectLatestContractsBySlug(contracts));
};

// The catalog only changes when the catalog manager synchronises it, while the connector page
// refreshes its connector every few seconds: one listing serves every request for a minute.
const CATALOG_IDENTITY_INDEX_TTL = 60 * 1000;
let catalogIdentityIndexCache: { expiresAt: number; index: Promise<CatalogIdentityIndex> } | null = null;

export const resetCatalogIdentityIndexCache = () => {
  catalogIdentityIndexCache = null;
};

export const loadCatalogIdentityIndex = async () => {
  const now = Date.now();
  if (catalogIdentityIndexCache && catalogIdentityIndexCache.expiresAt > now) {
    return catalogIdentityIndexCache.index;
  }
  const index = listCatalogIdentityIndex();
  catalogIdentityIndexCache = { expiresAt: now + CATALOG_IDENTITY_INDEX_TTL, index };
  // A failed listing is not kept: the next request lists the catalog again.
  index.catch(() => {
    if (catalogIdentityIndexCache?.index === index) {
      catalogIdentityIndexCache = null;
    }
  });
  return index;
};

const needsCatalog = (connector: IdentityConnector) => !isManagedConnector(connector) && !connector.built_in;

// Batch function of the per-request loader: one catalog index for every connector of the request.
export const batchConnectorCatalogIdentities = async (_context: AuthContext, _user: AuthUser, connectors: IdentityConnector[]) => {
  const index = connectors.some(needsCatalog) ? await loadCatalogIdentityIndex() : buildCatalogIdentityIndex([]);
  return connectors.map((connector) => resolveConnectorCatalogIdentity(connector, index));
};

export const connectorCatalogIdentity = async (context: AuthContext, user: AuthUser, connector: IdentityConnector) => {
  const loader = context.batch?.connectorCatalogIdentityBatchLoader;
  if (loader) {
    return loader.load(connector);
  }
  const [identity] = await batchConnectorCatalogIdentities(context, user, [connector]);
  return identity;
};

export const connectorCatalogIdentityOptions = async (_context: AuthContext) => {
  const index = await loadCatalogIdentityIndex();
  return [...index.bySlug.values()]
    .map((contract) => ({
      slug: contract.slug,
      title: contract.title,
      logo: contract.logo_uri || null,
      connector_type: contract.connector_type,
      short_description: contract.short_description ?? null,
    }))
    .sort((a, b) => a.title.localeCompare(b.title));
};

export const connectorCatalogIdentityUpdate = async (context: AuthContext, user: AuthUser, id: string, slug: string | null | undefined) => {
  const connector = await storeLoadById(context, user, id, ENTITY_TYPE_CONNECTOR) as unknown as BasicStoreEntityConnector;
  if (!connector) {
    throw FunctionalError('No connector found with the specified ID', { id });
  }
  if (isManagedConnector(connector)) {
    throw FunctionalError('The catalog entry of a managed connector comes from its deployment', { id });
  }
  if (connector.built_in) {
    throw FunctionalError('A built-in connector has no catalog entry', { id });
  }
  let catalogSlug: string | null = null;
  if (isNotEmptyField(slug)) {
    const index = await loadCatalogIdentityIndex();
    const contract = findCatalogContractBySlug(index, slug);
    if (!contract) {
      throw FunctionalError('No catalog entry found with this slug', { id, slug });
    }
    catalogSlug = contract.slug;
  }
  const patch = { catalog_slug_manual: catalogSlug };
  const { element } = await patchAttribute<BasicStoreEntityConnector>(context, user, id, ENTITY_TYPE_CONNECTOR, patch);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: catalogSlug
      ? `binds ${ENTITY_TYPE_CONNECTOR} \`${element.name}\` to the catalog entry \`${catalogSlug}\``
      : `clears the catalog entry chosen for ${ENTITY_TYPE_CONNECTOR} \`${element.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_CONNECTOR, input: patch },
  });
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
  return completeConnector(element);
};
