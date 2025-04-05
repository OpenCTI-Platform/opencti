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
    { name: 'manifest', label: 'Manifest', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixTheme) => stix.name,
  converter_2_1: convertThemeToStix,
};

registerDefinition(THEME_DEFINITION);
