export interface GlobalExportBundleItem {
  key: string;
  label: string;
}

export type GlobalExportCategoryKind = 'children' | 'flat' | 'placeholder';

export interface GlobalExportBundleCategory {
  key: string;
  label: string;
  kind: GlobalExportCategoryKind;
  items?: GlobalExportBundleItem[];
}

export const EXPORT_CATEGORIES: GlobalExportBundleCategory[] = [
  {
    key: 'ingestion',
    label: 'Ingestion',
    kind: 'children',
    items: [
      { key: 'Playbook', label: 'Playbooks' },
      { key: 'Form', label: 'Forms' },
    ],
  },
  {
    key: 'Workspace',
    label: 'Custom Dashboards',
    kind: 'flat',
  },
  {
    key: 'CustomView',
    label: 'Custom Views',
    kind: 'flat',
  },
  {
    key: 'Feed',
    label: 'Feeds',
    kind: 'children',
    items: [
      { key: 'IngestionCsv', label: 'CSV Feeds' },
      { key: 'IngestionTaxii', label: 'Taxii Feeds' },
      { key: 'IngestionJson', label: 'JSON Feeds' },
      { key: 'IngestionRss', label: 'RSS Feeds' },
    ],
  },
  {
    key: 'FintelTemplate',
    label: 'Fintel Templates',
    kind: 'flat',
  },
];

export const getDefaultCheckedCategoryItems = (): Record<string, string[]> => {
  return Object.fromEntries(
    EXPORT_CATEGORIES
      .filter((category) => category.kind !== 'placeholder')
      .map((category) => {
        const keys = category.kind === 'flat' ? [category.key] : (category.items ?? []).map((item) => item.key);
        return [category.key, keys];
      }),
  );
};
