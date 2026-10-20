import type { MenuEntry } from '../common/menus/NavToolbarMenu';

// Pure data (no component import): collected by the pages search through its `*.entries.ts(x)` name.
export const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/data/import/file',
    label: 'Global files',
    keywords: ['upload', 'import', 'stix', 'pdf', 'document'],
  },
  {
    path: '/dashboard/data/import/draft',
    label: 'Drafts',
    keywords: ['draft', 'staging', 'review', 'sandbox'],
  },
  {
    path: '/dashboard/data/import/workbench',
    label: 'Analyst workbenches',
    keywords: ['workbench', 'validate', 'pending import'],
  },
];
