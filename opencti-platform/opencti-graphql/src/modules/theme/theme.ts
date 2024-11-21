import { v4 as uuidv4 } from 'uuid';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { registerDefinition, type ModuleDefinition } from '../../schema/module';
import { type StixTheme, type StoreEntityTheme } from './theme-types';
import convertThemeToStix from './theme-converter';
import { ENTITY_TYPE_THEME } from '../../schema/internalObject';

export const THEME_DEFINITION: ModuleDefinition<StoreEntityTheme, StixTheme> = {
  type: {
    id: 'theme',
    name: ENTITY_TYPE_THEME,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_THEME]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'theme_background', label: 'Theme background', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'theme_paper', label: 'Theme paper', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'theme_nav', label: 'Theme navigation', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'theme_primary', label: 'Theme primary', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'theme_secondary', label: 'Theme secondary', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'theme_accent', label: 'Theme accent', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'theme_logo', label: 'Theme logo', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'theme_logo_collapsed', label: 'Theme logo collapsed', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'theme_logo_login', label: 'Theme logo login', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixTheme) => stix.name,
  converter: convertThemeToStix,
};

registerDefinition(THEME_DEFINITION);
