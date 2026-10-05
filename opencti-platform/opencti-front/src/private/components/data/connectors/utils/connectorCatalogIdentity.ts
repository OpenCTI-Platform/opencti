export type ConnectorCatalogIdentitySource = 'composer' | 'manual' | 'reported' | 'name' | '%future added value';

export interface ConnectorCatalogIdentityValue {
  readonly slug: string;
  readonly title: string;
  readonly logo?: string | null;
  readonly source: ConnectorCatalogIdentitySource;
}

const compactName = (value: string | null | undefined) => (value ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');

export const isSameConnectorName = (left: string | null | undefined, right: string | null | undefined) => {
  return compactName(left) !== '' && compactName(left) === compactName(right);
};

// How the catalog entry of a self-deployed connector was found. The composer contract of a
// managed connector needs no explanation.
export const catalogIdentityHint = (
  source: ConnectorCatalogIdentitySource | null | undefined,
  t_i18n: (key: string) => string,
): string | null => {
  if (source === 'reported') return t_i18n('Reported by the connector');
  if (source === 'name') return t_i18n('Identified by name');
  if (source === 'manual') return t_i18n('Chosen by hand');
  return null;
};

export const catalogIdentityHintDescription = (
  source: ConnectorCatalogIdentitySource | null | undefined,
  t_i18n: (key: string) => string,
): string | null => {
  if (source === 'reported') return t_i18n('The connector image reported this catalog entry when the connector registered.');
  if (source === 'name') return t_i18n('The name of the connector matches this catalog entry only. Change it if it is not the right one.');
  if (source === 'manual') return t_i18n('Chosen on this page. The choice is kept when the connector restarts or is renamed.');
  return null;
};

// Only a self-deployed connector takes a catalog entry by hand: a managed connector gets it from
// its deployment, a built-in connector is part of the platform.
export const canIdentifyConnector = (connector: { readonly is_managed?: boolean | null; readonly built_in?: boolean | null }) => {
  return !connector.is_managed && !connector.built_in;
};

// Catalog entries of the connector's type first: an analysis connector runs an import file image.
const COMPATIBLE_CATALOG_TYPES: Record<string, string[]> = {
  INTERNAL_ANALYSIS: ['INTERNAL_ANALYSIS', 'INTERNAL_IMPORT_FILE'],
};

export const isCompatibleCatalogType = (connectorType: string | null | undefined, catalogType: string | null | undefined) => {
  if (!connectorType || !catalogType) return false;
  return (COMPATIBLE_CATALOG_TYPES[connectorType] ?? [connectorType]).includes(catalogType);
};

export const sortCatalogOptionsForConnector = <T extends { readonly title: string; readonly connector_type?: string | null }>(
  options: readonly T[],
  connectorType: string | null | undefined,
): T[] => {
  return [...options].sort((a, b) => {
    const aCompatible = isCompatibleCatalogType(connectorType, a.connector_type);
    const bCompatible = isCompatibleCatalogType(connectorType, b.connector_type);
    if (aCompatible !== bCompatible) {
      return aCompatible ? -1 : 1;
    }
    return a.title.localeCompare(b.title);
  });
};
