import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { createEntity, deleteElementById, updateAttribute } from '../../../src/database/middleware';
import { getClientBase } from '../../../src/database/redis';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_VULNERABILITY } from '../../../src/modules/vulnerability/vulnerability-types';
import { addIngestionDeduplicationRule, deleteIngestionDeduplicationRule } from '../../../src/modules/ingestionDeduplication/ingestionDeduplicationRule-domain';

const lastImportedHash = (stixId: string) => getClientBase().hget(`dedup:${stixId}`, ADMIN_USER.id);

describe('Ingestion deduplication', () => {
  const stixId = `attack-pattern--${uuidv4()}`;
  const baseInput = {
    stix_id: stixId,
    name: `Deduplicated attack pattern ${stixId}`,
    description: 'imported',
    modified: '2024-01-01T00:00:00.000Z',
    update: true,
  };
  let ruleId: string;
  let attackPatternId: string;

  beforeAll(async () => {
    const rule = await addIngestionDeduplicationRule(testContext, ADMIN_USER, {
      user_id: ADMIN_USER.id,
      target_type: ENTITY_TYPE_ATTACK_PATTERN,
      excluded_fields: ['modified'],
    });
    ruleId = rule.id;
  });

  afterAll(async () => {
    await deleteIngestionDeduplicationRule(testContext, ADMIN_USER, ruleId);
    if (attackPatternId) {
      await deleteElementById(testContext, ADMIN_USER, attackPatternId, ENTITY_TYPE_ATTACK_PATTERN);
    }
  });

  it('should record the content of an imported entity', async () => {
    const result = await createEntity(testContext, ADMIN_USER, baseInput, ENTITY_TYPE_ATTACK_PATTERN, { complete: true });
    attackPatternId = result.element.id;
    expect(result.isCreation).toBe(true);
    expect(await lastImportedHash(stixId)).toBeTruthy();
  });

  it('should skip an import where only excluded fields changed', async () => {
    const result = await createEntity(testContext, ADMIN_USER, { ...baseInput, modified: '2024-06-01T00:00:00.000Z' }, ENTITY_TYPE_ATTACK_PATTERN, { complete: true });
    expect(result.isCreation).toBe(false);
    expect(result.event).toBeNull();
    expect(new Date(result.element.modified).toISOString()).toBe(baseInput.modified);
  });

  it('should import a changed entity', async () => {
    const hashBefore = await lastImportedHash(stixId);
    const result = await createEntity(testContext, ADMIN_USER, { ...baseInput, description: 'changed at the source' }, ENTITY_TYPE_ATTACK_PATTERN, { complete: true });
    expect(result.element.description).toBe('changed at the source');
    expect(await lastImportedHash(stixId)).not.toBe(hashBefore);
  });

  it('should import again after a change made elsewhere', async () => {
    await updateAttribute(testContext, ADMIN_USER, attackPatternId, ENTITY_TYPE_ATTACK_PATTERN, [{ key: 'description', value: ['edited in the platform'] }]);
    expect(await lastImportedHash(stixId)).toBeNull();
    const result = await createEntity(testContext, ADMIN_USER, { ...baseInput, description: 'changed at the source' }, ENTITY_TYPE_ATTACK_PATTERN, { complete: true });
    expect(result.element.description).toBe('changed at the source');
  });

  it('should create the entity again after its deletion', async () => {
    await deleteElementById(testContext, ADMIN_USER, attackPatternId, ENTITY_TYPE_ATTACK_PATTERN);
    expect(await lastImportedHash(stixId)).toBeNull();
    const result = await createEntity(testContext, ADMIN_USER, baseInput, ENTITY_TYPE_ATTACK_PATTERN, { complete: true });
    attackPatternId = result.element.id;
    expect(result.isCreation).toBe(true);
  });

  it('should never record a type outside the allowlist', async () => {
    const vulnerabilityStixId = `vulnerability--${uuidv4()}`;
    const result = await createEntity(testContext, ADMIN_USER, { stix_id: vulnerabilityStixId, name: `CVE-DEDUP-${uuidv4()}`, update: true }, ENTITY_TYPE_VULNERABILITY, { complete: true });
    expect(await lastImportedHash(vulnerabilityStixId)).toBeNull();
    await deleteElementById(testContext, ADMIN_USER, result.element.id, ENTITY_TYPE_VULNERABILITY);
  });
});
