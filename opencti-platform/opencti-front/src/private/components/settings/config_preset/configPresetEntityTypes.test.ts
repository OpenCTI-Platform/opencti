import { describe, expect, it } from 'vitest';
import { translateConfigPresetEntityTypes } from './configPresetEntityTypes';

const t_i18n = (key: string) => ({ 'entity_Attack-Pattern': 'Motif d\'attaque', entity_Malware: 'Malware' }[key] ?? key);

describe('translateConfigPresetEntityTypes', () => {
  it('translates each type, and keeps the name of a type that has no translation', () => {
    expect(translateConfigPresetEntityTypes(t_i18n, 'Attack-Pattern, Malware, Unknown')).toEqual('Motif d\'attaque, Malware, Unknown');
  });
});
