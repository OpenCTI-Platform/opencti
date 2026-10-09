export interface GlobalExportBundleItem {
  key: string;
  label: string;
}

export interface GlobalExportBundleCategory {
  key: string;
  label: string;
  items: GlobalExportBundleItem[];
}

export const EXPORT_CATEGORIES: GlobalExportBundleCategory[] = [
  {
    key: 'Security & Access',
    label: 'Security & Access',
    items: [
      { key: 'SettingsPolicies', label: 'Policies' },
    ],
  },
  {
    key: 'Data Model',
    label: 'Data Model',
    items: [
      { key: 'SettingsHiddenEntityTypes', label: 'Hidden entity types' },
    ],
  },
  {
    key: 'Settings',
    label: 'Platform Settings',
    items: [
      { key: 'SettingsTheme', label: 'Theme (colors, logos, platform name...)' },
      { key: 'SettingsLanguage', label: 'Language' },
      { key: 'SettingsMessages', label: 'Messages (banner)' },
    ],
  },
];

export const getDefaultCheckedCategoryItems = (): Record<string, string[]> => {
  return Object.fromEntries(
    EXPORT_CATEGORIES.map((category) => [category.key, category.items.map((item) => item.key)]),
  );
};
