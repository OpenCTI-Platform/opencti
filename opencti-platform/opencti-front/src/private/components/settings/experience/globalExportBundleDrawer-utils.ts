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

export interface GlobalExportBundleSelection {
  bundleName: string;
  categories: Record<string, string[]>;
}

export const EXPORT_CATEGORIES: GlobalExportBundleCategory[] = [
  {
    key: 'ingestion',
    label: 'Ingestion',
    kind: 'children',
    items: [
      { key: 'playbooks', label: 'Playbooks' },
      { key: 'form_intakes', label: 'Forms' },
    ],
  },
  {
    key: 'dashboards',
    label: 'Custom Dashboards',
    kind: 'flat',
  },
  {
    key: 'custom',
    label: 'Custom Views',
    kind: 'flat',
  },
  {
    key: 'feeds',
    label: 'Feeds',
    kind: 'children',
    items: [
      { key: 'feeds_csv', label: 'CSV Feeds' },
      { key: 'feeds_taxii', label: 'Taxii Feeds' },
      { key: 'feeds_json', label: 'JSON Feeds' },
      { key: 'feeds_rss', label: 'RSS Feeds' },
    ],
  },
  {
    key: 'fintel_templates',
    label: 'Fintel Templates',
    kind: 'flat',
  },
];

export const getDefaultCheckedCategoryItems = (): Record<string, string[]> => {
  return Object.fromEntries(
    EXPORT_CATEGORIES
      .filter((category) => category.kind !== 'placeholder')
      .map((category) => [
        category.key,
        category.kind === 'flat' ? [category.key] : (category.items ?? []).map((item) => item.key),
      ]),
  );
};
