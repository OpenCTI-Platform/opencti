import { describe, expect, it } from 'vitest';
import { convertTypeToStixType } from '../../../src/database/stix-2-1-converter';
import { generateInternalType } from '../../../src/schema/schemaUtils';
import { isStixCoreRelationship } from '../../../src/schema/stixCoreRelationship';
import { openVocabularies } from '../../../src/modules/vocabulary/vocabulary-utils';
import { ENTITY_TYPE_PROCEDURE } from '../../../src/modules/procedure/procedure-types';

describe('Procedure schema foundations', () => {
  it('maps Procedure to x-opencti-procedure', () => {
    expect(convertTypeToStixType(ENTITY_TYPE_PROCEDURE)).toBe('x-opencti-procedure');
  });
  it('maps x-opencti-procedure back to Procedure', () => {
    expect(generateInternalType({ type: 'x-opencti-procedure' })).toBe('Procedure');
  });
  it('registers implements-technique as a core relationship', () => {
    expect(isStixCoreRelationship('implements-technique')).toBe(true);
  });
  it('declares procedure_type_ov with reporting as its only default value', () => {
    expect(openVocabularies.procedure_type_ov).toEqual([{ key: 'reporting' }]);
  });
  it('adds the PDF platforms in lowercase', () => {
    const keys = openVocabularies.platforms_ov.map((v) => v.key);
    expect(keys).toEqual(expect.arrayContaining(['windows', 'linux', 'macos', 'network', 'cloud', 'ics', 'containers', 'saas', 'office suite', 'identity provider', 'google workspace', 'azure ad', 'mobile']));
  });
});
