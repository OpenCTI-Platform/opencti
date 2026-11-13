import type { NormalizedSchema } from '../data/schemaTypes';
import { DEFAULT_ENABLED_CATEGORIES } from '../shared/theme/typeAppearance';
import { type CanvasSnapshot, EMPTY_SNAPSHOT } from './canvasSnapshot';

export type ViewIcon = 'layers' | 'target' | 'tree' | 'folder' | 'tag' | 'bookmark';

export interface SavedView {
  id: string;
  name: string;
  icon: ViewIcon;
  builtin: boolean;
  snapshot: CanvasSnapshot;
}

interface BuiltinView extends Omit<SavedView, 'snapshot'> {
  resolve: (schema: NormalizedSchema) => CanvasSnapshot;
}

const existing = (schema: NormalizedSchema, ids: string[]) => ids.filter((id) => schema.types.has(id));

const pick = (ids: string[], overrides: Partial<CanvasSnapshot> = {}) => (schema: NormalizedSchema): CanvasSnapshot => ({
  ...EMPTY_SNAPSHOT,
  ...overrides,
  pinnedTypeIds: existing(schema, ids),
});

export const DEFAULT_VIEW_ID = 'builtin:threat-intel';

export const BUILTIN_VIEWS: BuiltinView[] = [
  {
    id: DEFAULT_VIEW_ID,
    name: 'Threat intelligence core',
    icon: 'target',
    builtin: true,
    resolve: pick(['Intrusion-Set', 'Malware', 'Attack-Pattern', 'Indicator', 'Vulnerability', 'Campaign', 'Sector']),
  },
  {
    id: 'builtin:observables',
    name: 'Observables & indicators',
    icon: 'layers',
    builtin: true,
    resolve: pick(['Indicator', 'Observed-Data', 'IPv4-Addr', 'IPv6-Addr', 'Domain-Name', 'Url', 'StixFile', 'Email-Addr', 'Network-Traffic', 'Autonomous-System']),
  },
  {
    id: 'builtin:containers',
    name: 'Reports & cases',
    icon: 'folder',
    builtin: true,
    resolve: pick(['Report', 'Grouping', 'Note', 'Opinion', 'Case-Incident', 'Case-Rfi', 'Case-Rft', 'Container'], { showInheritance: true, showRelations: false }),
  },
  {
    id: 'builtin:meta',
    name: 'Meta objects & markings',
    icon: 'tag',
    builtin: true,
    resolve: pick(['Stix-Meta-Object', 'Marking-Definition', 'Label', 'External-Reference', 'Kill-Chain-Phase', 'Vocabulary'], { showInheritance: true, showRelations: false }),
  },
  {
    id: 'builtin:hierarchy',
    name: 'Full type hierarchy',
    icon: 'tree',
    builtin: true,
    resolve: (schema) => ({
      ...EMPTY_SNAPSHOT,
      enabledCategories: DEFAULT_ENABLED_CATEGORIES,
      pinnedTypeIds: schema.typeIds.filter((id) => schema.types.get(id)?.category !== 'Internal'),
      showInheritance: true,
      showRelations: false,
      direction: 'LR',
    }),
  },
];

export const resolveBuiltinViews = (schema: NormalizedSchema): SavedView[] => BUILTIN_VIEWS
  .map(({ resolve, ...view }) => ({ ...view, snapshot: resolve(schema) }));
