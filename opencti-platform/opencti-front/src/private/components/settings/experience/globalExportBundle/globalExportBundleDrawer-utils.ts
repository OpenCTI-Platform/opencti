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
    key: 'FintelTemplate',
    label: 'Fintel Templates',
    kind: 'flat',
  },
  {
    key: 'Settings',
    label: 'Platform Settings',
    kind: 'children',
    items: [
      { key: 'SettingsBranding', label: 'Branding' },
      { key: 'SettingsTheme', label: 'Theme (colors, logos)' },
      { key: 'SettingsLanguage', label: 'Language & translations' },
      { key: 'SettingsMessages', label: 'Messages (banner, login, consent)' },
      { key: 'SettingsHiddenEntityTypes', label: 'Hidden entity types' },
    ],
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
