import { IngestionConnector } from '@components/integrations/catalog/types';

// Catalog manifests are external JSON: a contract may come without a title.
// Fall back to the slug here so every consumer (cards, search, links, detail page) gets a usable title.
const parseIngestionConnector = (contract: string): IngestionConnector => {
  const connector = JSON.parse(contract) as IngestionConnector;
  return { ...connector, title: connector.title ?? connector.slug ?? '' };
};

export default parseIngestionConnector;
