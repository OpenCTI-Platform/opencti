import { expect, it } from 'vitest';
import { getAvailableSettings } from '../../../src/modules/entitySetting/entitySetting-utils';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';

it('should Report entitySettings options correctly generated', () => {
  const settingsAttributesReport = getAvailableSettings(ENTITY_TYPE_CONTAINER_REPORT);
  expect(settingsAttributesReport.length).toEqual(4);
});

it('should Attack Pattern entitySettings options correctly generated', () => {
  const settingsAttributesAttackPattern = getAvailableSettings(ENTITY_TYPE_ATTACK_PATTERN);
  expect(settingsAttributesAttackPattern.length).toEqual(4);
});
