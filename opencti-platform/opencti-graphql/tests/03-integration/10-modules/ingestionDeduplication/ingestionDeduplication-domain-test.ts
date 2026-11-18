import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { ADMIN_USER, getAuthUser, getUserIdByEmail, testContext, USER_EDITOR } from '../../../utils/testQuery';
import { ENABLED_FEATURE_FLAGS } from '../../../../src/config/conf';
import createSchema from '../../../../src/graphql/schema';
import { KNOWLEDGE_KNFORMINTAKE, SYSTEM_USER } from '../../../../src/utils/access';
import { addUser, userDelete } from '../../../../src/modules/user/user-domain';
import { addIngestion, ingestionDelete } from '../../../../src/modules/ingestion/ingestion-rss-domain';
import { addIngestion as addTaxiiPush, ingestionDelete as deleteTaxiiPush } from '../../../../src/modules/ingestion/ingestion-taxii-collection-domain';
import { connectorIdFromIngestId } from '../../../../src/domain/connector';
import { generateStandardId } from '../../../../src/schema/identifier';
import { ENTITY_TYPE_MALWARE, ENTITY_TYPE_TOOL } from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_VULNERABILITY } from '../../../../src/modules/vulnerability/vulnerability-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import { createEntity, deleteElementById, updateAttribute } from '../../../../src/database/middleware';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { redisDeleteIngestionRecord, redisGetIngestionRecord } from '../../../../src/database/redis';
import { findUnchangedEntity, type IngestionDeduplication, prepareIngestionDeduplication, recordIngestion } from '../../../../src/database/ingestionDeduplication';
import {
  addIngestionDeduplicationRule,
  deleteIngestionDeduplicationRule,
  fieldPatchIngestionDeduplicationRule,
  findById,
  findHashableFields,
  findIngestionDeduplicationRules,
  findUserIngestionUsages,
} from '../../../../src/modules/ingestionDeduplication/ingestionDeduplicationRule-domain';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { BasicStoreEntity } from '../../../../src/types/store';

const malwareInput = (overrides: Record<string, unknown> = {}) => ({
  stix_id: 'malware--1d1a6aa1-6a17-4a5e-8a07-2c7b4a1b0d01',
  name: 'Deduplication domain malware',
  description: 'imported',
  modified: '2024-01-01T00:00:00.000Z',
  update: true,
  ...overrides,
});

describe('Ingestion deduplication domain', () => {
  let connectorUserId: string;
  let connectorUser: AuthUser;
  let malwareRuleId: string;

  const checkMalware = async (input: Record<string, unknown>, context: AuthContext = testContext) => {
    return await prepareIngestionDeduplication(context, connectorUser, input, ENTITY_TYPE_MALWARE) as IngestionDeduplication;
  };
  const importedMalware = { updated_at: '2024-01-01T00:00:00.000Z' };
  const isUnchanged = async (deduplication: IngestionDeduplication) => (await findUnchangedEntity(deduplication, async () => importedMalware)) !== undefined;
  const forgetMalware = (deduplication: IngestionDeduplication) => redisDeleteIngestionRecord(deduplication.standardId, connectorUserId);
  const loadMalware = (id: string) => () => storeLoadById<BasicStoreEntity>(testContext, connectorUser, id, ENTITY_TYPE_MALWARE);

  beforeAll(async () => {
    const created = await addUser(testContext, ADMIN_USER, {
      name: 'ingestion dedup domain',
      password: 'ingestionDedup',
      user_email: 'ingestion-dedup-domain@opencti.invalid',
    });
    connectorUserId = created.id;
    connectorUser = { ...ADMIN_USER, id: connectorUserId, internal_id: connectorUserId, draft_context: undefined } as AuthUser;
  });

  afterAll(async () => {
    const rules = await findIngestionDeduplicationRules(testContext, connectorUserId);
    for (let i = 0; i < rules.length; i += 1) {
      await deleteIngestionDeduplicationRule(testContext, ADMIN_USER, rules[i].id);
    }
    await userDelete(testContext, SYSTEM_USER, connectorUserId);
  });

  describe('Setting up rules', () => {
    it('should deduplicate a type for a user once an administrator adds a rule', async () => {
      // GIVEN a connector user without any rule
      expect(await findIngestionDeduplicationRules(testContext, connectorUserId)).toHaveLength(0);
      // WHEN an administrator deduplicates its malware, ignoring the modified date
      const rule = await addIngestionDeduplicationRule(testContext, ADMIN_USER, { user_id: connectorUserId, target_type: ENTITY_TYPE_MALWARE, excluded_fields: ['modified'] });
      malwareRuleId = rule.id;
      // THEN the user has this rule
      const rules = await findIngestionDeduplicationRules(testContext, connectorUserId);
      expect(rules.map((r) => r.target_type)).toEqual([ENTITY_TYPE_MALWARE]);
      expect(rules[0].excluded_fields).toEqual(['modified']);
    });

    it('should refuse a second rule for a type the user already deduplicates', async () => {
      // GIVEN the user deduplicates its malware
      // WHEN an administrator adds another rule on malware for the same user
      const adding = addIngestionDeduplicationRule(testContext, ADMIN_USER, { user_id: connectorUserId, target_type: ENTITY_TYPE_MALWARE });
      // THEN it is refused
      await expect(adding).rejects.toThrow('A deduplication rule already exists for this user and entity type');
    });

    it('should never deduplicate a type whose updates must always reach the platform', async () => {
      // GIVEN vulnerabilities, which are not in the allowlist
      // WHEN an administrator adds a rule on vulnerabilities
      const adding = addIngestionDeduplicationRule(testContext, ADMIN_USER, { user_id: connectorUserId, target_type: ENTITY_TYPE_VULNERABILITY });
      // THEN it is refused
      await expect(adding).rejects.toThrow('Deduplication is not available for this entity type');
    });

    it('should refuse a rule for a user that does not exist', async () => {
      // GIVEN a user id no account has
      // WHEN an administrator adds a rule for it
      const adding = addIngestionDeduplicationRule(testContext, ADMIN_USER, { user_id: uuidv4(), target_type: ENTITY_TYPE_MALWARE });
      // THEN it is refused
      await expect(adding).rejects.toThrow('The user of a deduplication rule must exist');
    });

    it('should delete the rules of a user deleted by an administrator', async () => {
      // GIVEN a user with a rule
      const deletedUser = await addUser(testContext, ADMIN_USER, {
        name: 'ingestion dedup deleted user',
        password: 'ingestionDedup',
        user_email: 'ingestion-dedup-deleted@opencti.invalid',
      });
      const rule = await addIngestionDeduplicationRule(testContext, ADMIN_USER, { user_id: deletedUser.id, target_type: ENTITY_TYPE_MALWARE });
      // WHEN an administrator deletes the user
      await userDelete(testContext, ADMIN_USER, deletedUser.id);
      // THEN its rule is gone too
      expect(await findById(testContext, ADMIN_USER, rule.id)).toBeFalsy();
    });

    it('should delete the rules of a deleted user while the feature is disabled', async () => {
      // GIVEN a user with a rule, and the feature disabled afterwards
      const deletedUser = await addUser(testContext, ADMIN_USER, {
        name: 'ingestion dedup deleted user flag off',
        password: 'ingestionDedup',
        user_email: 'ingestion-dedup-deleted-flag-off@opencti.invalid',
      });
      const rule = await addIngestionDeduplicationRule(testContext, ADMIN_USER, { user_id: deletedUser.id, target_type: ENTITY_TYPE_MALWARE });
      const enabledFlags = ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length);
      try {
        // WHEN an administrator deletes the user
        await userDelete(testContext, ADMIN_USER, deletedUser.id);
      } finally {
        ENABLED_FEATURE_FLAGS.push(...enabledFlags);
      }
      // THEN its rule is gone too, so it cannot come back once the feature is enabled again
      expect(await findById(testContext, ADMIN_USER, rule.id)).toBeFalsy();
    });

    it('should only accept an expiration in whole seconds', async () => {
      // GIVEN an administrator setting an expiration
      // WHEN it is zero on a new rule, a fraction on an existing one, or negative after a valid one in the same edit
      const adding = () => addIngestionDeduplicationRule(testContext, ADMIN_USER, { user_id: connectorUserId, target_type: ENTITY_TYPE_TOOL, ttl: 0 });
      const patching = () => fieldPatchIngestionDeduplicationRule(testContext, ADMIN_USER, malwareRuleId, [{ key: 'ttl', value: [1.5] }]);
      const patchingTwice = () => fieldPatchIngestionDeduplicationRule(testContext, ADMIN_USER, malwareRuleId, [{ key: 'ttl', value: [600] }, { key: 'ttl', value: [-1] }]);
      // THEN all are refused
      await expect(adding()).rejects.toThrow('The expiration must be a positive number of seconds');
      await expect(patching()).rejects.toThrow('The expiration must be a positive number of seconds');
      await expect(patchingTwice()).rejects.toThrow('The expiration must be a positive number of seconds');
    });

    it('should accept an expiration sent as text, like any other number', async () => {
      // GIVEN the malware rule
      // WHEN an API client sends the expiration as a numeric string
      const patched = await fieldPatchIngestionDeduplicationRule(testContext, ADMIN_USER, malwareRuleId, [{ key: 'ttl', value: ['3600'] }]);
      // THEN it is stored as a number of seconds
      expect(patched.ttl).toEqual(3600);
    });

    it('should leave out the dates sources move on every run when no field is given', async () => {
      // GIVEN an administrator adding a rule through the API
      // WHEN no excluded field is given
      const rule = await addIngestionDeduplicationRule(testContext, ADMIN_USER, { user_id: connectorUserId, target_type: ENTITY_TYPE_TOOL });
      // THEN the modified dates are excluded, as the form offers by default
      expect(rule.excluded_fields).toEqual(['modified', 'x_opencti_modified_at']);
      await deleteIngestionDeduplicationRule(testContext, ADMIN_USER, rule.id);
    });

    it('should keep the type of a rule, which identifies it', async () => {
      // GIVEN the malware rule
      // WHEN an administrator tries to turn it into a tool rule
      const patching = fieldPatchIngestionDeduplicationRule(testContext, ADMIN_USER, malwareRuleId, [{ key: 'target_type', value: [ENTITY_TYPE_TOOL] }]);
      // THEN it is refused: only the excluded fields and the expiration can change
      await expect(patching).rejects.toThrow('Only the excluded fields and the expiration of a deduplication rule can be changed');
    });

    it('should show the rules of a user sorted by type, and among all the rules', async () => {
      // GIVEN the user also deduplicates its tools
      const toolRule = await addIngestionDeduplicationRule(testContext, ADMIN_USER, { user_id: connectorUserId, target_type: ENTITY_TYPE_TOOL });
      // WHEN its rules, then all the rules, are listed
      const userRules = await findIngestionDeduplicationRules(testContext, connectorUserId);
      const allRules = await findIngestionDeduplicationRules(testContext);
      // THEN both rules show, malware first, and the tool rule is among all the rules
      expect(userRules.map((r) => r.target_type)).toEqual([ENTITY_TYPE_MALWARE, ENTITY_TYPE_TOOL]);
      expect(allRules.map((r) => r.id)).toContain(toolRule.id);
      await deleteIngestionDeduplicationRule(testContext, ADMIN_USER, toolRule.id);
    });

    it('should offer the fields of the imported data of the type as excludable fields', () => {
      // GIVEN the platform schema
      const schema = createSchema();
      // WHEN an administrator picks malware, then vulnerability
      const malwareFields = findHashableFields(schema, ENTITY_TYPE_MALWARE);
      const vulnerabilityFields = findHashableFields(schema, ENTITY_TYPE_VULNERABILITY);
      // THEN malware offers its attributes and references but no technical field, and vulnerability nothing
      expect(malwareFields).toEqual(expect.arrayContaining(['name', 'description', 'modified', 'createdBy', 'objectLabel']));
      expect(malwareFields).not.toContain('clientMutationId');
      expect(vulnerabilityFields).toEqual([]);
    });

    it('should show the feeds running as the user, except the one being looked at', async () => {
      // GIVEN an RSS feed running as the connector user
      const feed = await addIngestion(testContext, ADMIN_USER, { name: 'ingestion dedup domain feed', uri: 'https://example.allowed.com/dedup-rss', user_id: connectorUserId });
      try {
        // WHEN the ingestions of the user are listed, from anywhere then from the feed's own connector
        const usages = await findUserIngestionUsages(testContext, ADMIN_USER, connectorUserId);
        const usagesFromTheFeed = await findUserIngestionUsages(testContext, ADMIN_USER, connectorUserId, connectorIdFromIngestId(feed.id));
        // THEN the feed shows, except when it is the one being looked at
        expect(usages.map((usage) => usage.id)).toContain(feed.id);
        expect(usagesFromTheFeed.map((usage) => usage.id)).not.toContain(feed.id);
      } finally {
        await ingestionDelete(testContext, ADMIN_USER, feed.id);
      }
    });

    it('should hide the feeds the reader cannot see', async () => {
      // GIVEN an RSS feed and a TAXII push collection restricted to the admin, both running as the connector user
      const feed = await addIngestion(testContext, ADMIN_USER, { name: 'ingestion dedup visible feed', uri: 'https://example.allowed.com/dedup-visible', user_id: connectorUserId });
      const restricted = await addTaxiiPush(testContext, ADMIN_USER, {
        name: 'ingestion dedup restricted collection',
        user_id: connectorUserId,
        authorized_members: [{ id: ADMIN_USER.id, access_right: 'admin' }],
      });
      try {
        // WHEN an editor who is not a member of the collection lists the ingestions of the user
        const editor = await getAuthUser(await getUserIdByEmail(USER_EDITOR.email));
        const usages = await findUserIngestionUsages(testContext, editor, connectorUserId);
        // THEN the feed shows, but not the collection, not even by name
        expect(usages.map((usage) => usage.id)).toContain(feed.id);
        expect(usages.map((usage) => usage.id)).not.toContain(restricted.id);
      } finally {
        await ingestionDelete(testContext, ADMIN_USER, feed.id);
        await deleteTaxiiPush(testContext, ADMIN_USER, restricted.id);
      }
    });
  });

  describe('Importing', () => {
    it('should import as usual what no rule covers', async () => {
      // GIVEN the user deduplicates malware only
      const draftContext = { ...testContext, draft_context: uuidv4() } as AuthContext;
      // WHEN it imports a tool, a vulnerability, a malware without stix id, an inferred malware, a malware in a draft, with a file,
      // with explicit operations, or replayed from the stream of another platform by a synchronization
      const checks = await Promise.all([
        prepareIngestionDeduplication(testContext, connectorUser, malwareInput({ name: 'tool' }), ENTITY_TYPE_TOOL),
        prepareIngestionDeduplication(testContext, connectorUser, { name: 'CVE-DEDUP', stix_id: 'vulnerability--0b0c8d7e-0000-4000-8000-000000000001' }, ENTITY_TYPE_VULNERABILITY),
        prepareIngestionDeduplication(testContext, connectorUser, malwareInput({ stix_id: undefined }), ENTITY_TYPE_MALWARE),
        prepareIngestionDeduplication(testContext, connectorUser, malwareInput(), ENTITY_TYPE_MALWARE, { fromRule: 'some-rule' }),
        prepareIngestionDeduplication(draftContext, connectorUser, malwareInput(), ENTITY_TYPE_MALWARE),
        prepareIngestionDeduplication(testContext, connectorUser, malwareInput({ files: [{}] }), ENTITY_TYPE_MALWARE),
        prepareIngestionDeduplication(testContext, connectorUser, malwareInput({ upsertOperations: [{ key: 'objectLabel', value: ['label--abc'], operation: 'add' }] }), ENTITY_TYPE_MALWARE),
        prepareIngestionDeduplication({ ...testContext, eventId: '1700000000000-0' } as AuthContext, connectorUser, malwareInput(), ENTITY_TYPE_MALWARE),
      ]);
      // THEN none of them is checked
      expect(checks.every((check) => check === null)).toBe(true);
    });

    it('should skip a malware sent again with only its modified date changed', async () => {
      // GIVEN a malware imported once by the user
      const firstImport = await checkMalware(malwareInput());
      await recordIngestion(firstImport, importedMalware);
      // WHEN the source sends it again with a new modified date
      const secondImport = await checkMalware(malwareInput({ modified: '2025-06-01T00:00:00.000Z' }));
      // THEN it is recognized as unchanged, under the standard id the entity gets
      expect(await isUnchanged(secondImport)).toBe(true);
      expect(secondImport.standardId).toEqual(generateStandardId(ENTITY_TYPE_MALWARE, malwareInput()));
      await forgetMalware(firstImport);
    });

    it('should import a malware the source has changed', async () => {
      // GIVEN a malware imported once by the user
      const firstImport = await checkMalware(malwareInput());
      await recordIngestion(firstImport, importedMalware);
      // WHEN the source sends it again with a new description
      const secondImport = await checkMalware(malwareInput({ description: 'changed at the source' }));
      // THEN it is imported
      expect(await isUnchanged(secondImport)).toBe(false);
      await forgetMalware(firstImport);
    });

    it('should compare a connector only with its own imports', async () => {
      // GIVEN a malware imported by the user
      const importByUser = await checkMalware(malwareInput());
      await recordIngestion(importByUser, importedMalware);
      // WHEN another user sends the same malware
      const importByAnother = { ...importByUser, userId: ADMIN_USER.id };
      // THEN it is not recognized
      expect(await isUnchanged(importByAnother)).toBe(false);
      await forgetMalware(importByUser);
    });

    it('should not mistake a synchronized import for a regular one', async () => {
      // GIVEN a malware imported once by the user
      const regularImport = await checkMalware(malwareInput());
      await recordIngestion(regularImport, importedMalware);
      // WHEN the same malware comes in a synchronized upsert, which replaces lists instead of adding to them
      const synchronizedImport = await checkMalware(malwareInput(), { ...testContext, synchronizedUpsert: true } as AuthContext);
      // THEN it is imported
      expect(await isUnchanged(synchronizedImport)).toBe(false);
      await forgetMalware(regularImport);
    });

    it('should import again once the confidence of the user changes', async () => {
      // GIVEN a malware imported once by the user
      const firstImport = await checkMalware(malwareInput());
      await recordIngestion(firstImport, importedMalware);
      // WHEN the user's confidence is lowered, or overridden for malware
      const lowered = { ...connectorUser, effective_confidence_level: { max_confidence: 50, overrides: [] } } as AuthUser;
      const malwareOverride = { entity_type: ENTITY_TYPE_MALWARE, max_confidence: 30 };
      const overridden = { ...connectorUser, effective_confidence_level: { max_confidence: 100, overrides: [malwareOverride] } } as AuthUser;
      const afterLowering = await prepareIngestionDeduplication(testContext, lowered, malwareInput(), ENTITY_TYPE_MALWARE) as IngestionDeduplication;
      const afterOverride = await prepareIngestionDeduplication(testContext, overridden, malwareInput(), ENTITY_TYPE_MALWARE) as IngestionDeduplication;
      // THEN the next import runs, since it may now change more, or less, of the malware
      expect(await isUnchanged(afterLowering)).toBe(false);
      expect(await isUnchanged(afterOverride)).toBe(false);
      await forgetMalware(firstImport);
    });

    it('should import again once the user records itself as creator', async () => {
      // GIVEN a malware imported once by the user, which is not recorded as creator
      const withoutCreators = { ...connectorUser, no_creators: true } as AuthUser;
      const firstImport = await prepareIngestionDeduplication(testContext, withoutCreators, malwareInput(), ENTITY_TYPE_MALWARE) as IngestionDeduplication;
      await recordIngestion(firstImport, importedMalware);
      // WHEN the user is recorded as creator again
      const withCreators = { ...connectorUser, no_creators: false } as AuthUser;
      const nextImport = await prepareIngestionDeduplication(testContext, withCreators, malwareInput(), ENTITY_TYPE_MALWARE) as IngestionDeduplication;
      // THEN the next import runs, so the user is added to the creators of the malware
      expect(await isUnchanged(nextImport)).toBe(false);
      await forgetMalware(firstImport);
    });

    it('should import again a malware whose author was missing at its import', async () => {
      // GIVEN an author the platform does not know yet
      const unknownAuthor = 'identity--7a1a6aa1-6a17-4a5e-8a07-2c7b4a1b0d03';
      // WHEN the user imports a malware by this author, which the platform accepts without it
      const input = malwareInput({ stix_id: 'malware--1d1a6aa1-6a17-4a5e-8a07-2c7b4a1b0d03', name: 'Deduplication domain partial malware', createdBy: unknownAuthor });
      const malware = await createEntity(testContext, connectorUser, input, ENTITY_TYPE_MALWARE);
      try {
        // THEN the import is not recorded, so the same payload is imported again once the author exists
        expect(malware.id).toBeTruthy();
        expect(await redisGetIngestionRecord(malware.standard_id, connectorUserId)).toBeNull();
      } finally {
        await deleteElementById(testContext, ADMIN_USER, malware.id, ENTITY_TYPE_MALWARE);
      }
    });

    it('should not record a form that leaves the existing malware as it is', async () => {
      // GIVEN a malware imported by the user
      const input = malwareInput({ stix_id: 'malware--1d1a6aa1-6a17-4a5e-8a07-2c7b4a1b0d06', name: 'Deduplication domain form malware' });
      const malware = await createEntity(testContext, connectorUser, input, ENTITY_TYPE_MALWARE);
      const firstImport = await checkMalware(input);
      try {
        // WHEN the same user submits a form changing it, while it can only create knowledge
        const formContext = { ...testContext, form_submission: true } as AuthContext;
        const createOnlyUser = { ...connectorUser, capabilities: [{ name: KNOWLEDGE_KNFORMINTAKE }] } as AuthUser;
        await createEntity(formContext, createOnlyUser, { ...input, description: 'sent by a form' }, ENTITY_TYPE_MALWARE);
        // THEN the form is not recorded, so the same payload is applied once the user can update knowledge
        expect((await redisGetIngestionRecord(malware.standard_id, connectorUserId))?.hash).toEqual(firstImport.hash);
      } finally {
        await deleteElementById(testContext, ADMIN_USER, malware.id, ENTITY_TYPE_MALWARE);
        await forgetMalware(firstImport);
      }
    });

    it('should import again after the rule is edited, with the new expiration', async () => {
      // GIVEN a malware imported once by the user
      const beforeEdit = await checkMalware(malwareInput());
      await recordIngestion(beforeEdit, importedMalware);
      // WHEN an administrator changes the expiration of the rule
      await fieldPatchIngestionDeduplicationRule(testContext, ADMIN_USER, malwareRuleId, [{ key: 'ttl', value: [7200] }]);
      const afterEdit = await checkMalware(malwareInput());
      // THEN the next import runs and is recorded for the new expiration
      expect(await isUnchanged(afterEdit)).toBe(false);
      expect(afterEdit.ttl).toEqual(7200);
      await forgetMalware(beforeEdit);
    });
  });

  describe('Changes made elsewhere', () => {
    it('should import again a malware changed by someone else', async () => {
      // GIVEN a malware imported by the user
      const input = malwareInput({ stix_id: 'malware--1d1a6aa1-6a17-4a5e-8a07-2c7b4a1b0d04', name: 'Deduplication domain edited malware' });
      const malware = await createEntity(testContext, connectorUser, input, ENTITY_TYPE_MALWARE);
      const deduplication = await checkMalware(input);
      try {
        expect(await findUnchangedEntity(deduplication, loadMalware(malware.id))).toBeDefined();
        // WHEN an analyst edits the malware
        await updateAttribute(testContext, ADMIN_USER, malware.id, ENTITY_TYPE_MALWARE, [{ key: 'description', value: ['edited in the platform'] }]);
        // THEN the same payload is imported again, so the source's content comes back
        expect(await findUnchangedEntity(deduplication, loadMalware(malware.id))).toBeUndefined();
      } finally {
        await deleteElementById(testContext, ADMIN_USER, malware.id, ENTITY_TYPE_MALWARE);
        await forgetMalware(deduplication);
      }
    });

    it('should import once more a malware created with its author, then skip it', async () => {
      // GIVEN an author known to the platform
      const author = await createEntity(testContext, ADMIN_USER, { name: 'Deduplication domain first author', identity_class: 'organization' }, ENTITY_TYPE_IDENTITY_ORGANIZATION);
      const input = malwareInput({ stix_id: 'malware--1d1a6aa1-6a17-4a5e-8a07-2c7b4a1b0d05', name: 'Deduplication domain first authored malware', createdBy: author.id });
      const deduplication = await checkMalware(input);
      try {
        // WHEN the user imports a malware by this author, which links the author after writing the malware
        const malware = await createEntity(testContext, connectorUser, input, ENTITY_TYPE_MALWARE);
        // THEN the next import runs once more, and the one after is skipped
        expect(await findUnchangedEntity(deduplication, loadMalware(malware.id))).toBeUndefined();
        await createEntity(testContext, connectorUser, input, ENTITY_TYPE_MALWARE);
        expect(await findUnchangedEntity(deduplication, loadMalware(malware.id))).toBeDefined();
        await deleteElementById(testContext, ADMIN_USER, malware.id, ENTITY_TYPE_MALWARE);
      } finally {
        await deleteElementById(testContext, ADMIN_USER, author.id, ENTITY_TYPE_IDENTITY_ORGANIZATION);
        await forgetMalware(deduplication);
      }
    });

    it('should import again a malware whose author was deleted', async () => {
      // GIVEN a malware imported by the user with its author, until its imports are skipped
      const author = await createEntity(testContext, ADMIN_USER, { name: 'Deduplication domain author', identity_class: 'organization' }, ENTITY_TYPE_IDENTITY_ORGANIZATION);
      const input = malwareInput({ stix_id: 'malware--1d1a6aa1-6a17-4a5e-8a07-2c7b4a1b0d02', name: 'Deduplication domain authored malware', createdBy: author.id });
      await createEntity(testContext, connectorUser, input, ENTITY_TYPE_MALWARE);
      const malware = await createEntity(testContext, connectorUser, input, ENTITY_TYPE_MALWARE);
      const deduplication = await checkMalware(input);
      try {
        expect(await findUnchangedEntity(deduplication, loadMalware(malware.id))).toBeDefined();
        // WHEN an analyst deletes the author, which removes it from the malware without any update event
        await deleteElementById(testContext, ADMIN_USER, author.id, ENTITY_TYPE_IDENTITY_ORGANIZATION);
        // THEN the same payload is imported again, so the source can bring the author back
        expect(await findUnchangedEntity(deduplication, loadMalware(malware.id))).toBeUndefined();
      } finally {
        await deleteElementById(testContext, ADMIN_USER, malware.id, ENTITY_TYPE_MALWARE);
        await forgetMalware(deduplication);
      }
    });
  });

  describe('Feature disabled', () => {
    it('should not check anything', async () => {
      // GIVEN a user deduplicating its malware
      const enabledFlags = ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length);
      try {
        // WHEN the feature is disabled and a malware is imported
        const check = await prepareIngestionDeduplication(testContext, connectorUser, malwareInput(), ENTITY_TYPE_MALWARE);
        // THEN the import is not checked
        expect(check).toBeNull();
      } finally {
        ENABLED_FEATURE_FLAGS.push(...enabledFlags);
      }
    });
  });
});
