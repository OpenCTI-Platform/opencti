export interface GlobalExportBundleItem {
  key: string;
  label: string;
}

export type GlobalExportCategoryKind = 'children' | 'placeholder';

export interface GlobalExportBundleCategory {
  key: string;
  label: string;
  kind: GlobalExportCategoryKind;
  items?: GlobalExportBundleItem[];
}

export const EXPORT_CATEGORIES: GlobalExportBundleCategory[] = [
  {
    key: 'Settings',
    label: 'Platform settings',
    kind: 'children',
    items: [
      { key: 'SettingsTheme', label: 'Theme (colors, logos, platform name, favicon...)' },
      { key: 'SettingsLanguage', label: 'Language' },
      { key: 'SettingsMessages', label: 'Messages (banner)' },
      { key: 'SettingsHiddenEntityTypes', label: 'Hidden entity types' },
    ],
  },
];

export const getDefaultCheckedCategoryItems = (): Record<string, string[]> => {
  return Object.fromEntries(
    EXPORT_CATEGORIES
      .filter((category) => category.kind !== 'placeholder')
      .map((category) => [category.key, (category.items ?? []).map((item) => item.key)]),
  );
};
