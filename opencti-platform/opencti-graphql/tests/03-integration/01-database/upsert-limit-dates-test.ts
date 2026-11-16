import { afterAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { addIncident } from '../../../src/domain/incident';
import { addCampaign } from '../../../src/domain/campaign';
import { addIntrusionSet } from '../../../src/domain/intrusionSet';
import { addMalware } from '../../../src/domain/malware';
import { addThreatActorGroup } from '../../../src/domain/threatActorGroup';
import { addThreatActorIndividual } from '../../../src/modules/threatActorIndividual/threatActorIndividual-domain';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../../../src/modules/threatActorIndividual/threatActorIndividual-types';
import { ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INCIDENT, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE, ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../../../src/schema/stixDomainObject';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { stixDomainObjectDelete } from '../../../src/domain/stixDomainObject';
import { FROM_START_STR, UNTIL_END_STR } from '../../../src/utils/format';
import type { AuthContext, AuthUser } from '../../../src/types/user';

// An upsert of an existing dated entity whose input leaves first_seen / last_seen out
// must not overwrite the stored dates with the FROM_START / UNTIL_END sentinels the
// domain add functions put in place of a missing date.

type AddFunction = (context: AuthContext, user: AuthUser, input: any) => Promise<any>;

const FIRST_SEEN = '2026-10-23T00:00:00.000Z';
const LAST_SEEN = '2026-11-04T00:00:00.000Z';
const CREATED = '2026-10-20T00:00:00.000Z';

const DATED_TYPES: { type: string; add: AddFunction }[] = [
  { type: ENTITY_TYPE_INCIDENT, add: addIncident },
  { type: ENTITY_TYPE_CAMPAIGN, add: addCampaign },
  { type: ENTITY_TYPE_INTRUSION_SET, add: addIntrusionSet },
  { type: ENTITY_TYPE_MALWARE, add: addMalware },
  { type: ENTITY_TYPE_THREAT_ACTOR_GROUP, add: addThreatActorGroup },
  { type: ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL, add: addThreatActorIndividual },
];

const iso = (date: unknown) => new Date(date as string).toISOString();

const createdIds: { id: string; type: string }[] = [];

const loadDates = async (id: string, type: string) => {
  const element = await storeLoadById(testContext, ADMIN_USER, id, type) as any;
  return { element, firstSeen: iso(element.first_seen), lastSeen: iso(element.last_seen) };
};

describe('Upsert of first_seen / last_seen limit dates', () => {
  afterAll(async () => {
    for (let i = 0; i < createdIds.length; i += 1) {
      await stixDomainObjectDelete(testContext, ADMIN_USER, createdIds[i].id, createdIds[i].type);
    }
  });

  it('should update the severity of an incident and keep its dates when the input has no dates', async () => {
    const name = `Upsert limit dates incident ${Date.now()}`;
    const incident = await addIncident(testContext, ADMIN_USER, { name, created: CREATED, first_seen: FIRST_SEEN, last_seen: LAST_SEEN, severity: 'low' });
    createdIds.push({ id: incident.id, type: ENTITY_TYPE_INCIDENT });
    const upserted = await addIncident(testContext, ADMIN_USER, { name, created: CREATED, severity: 'high' });
    expect(upserted.id).toBe(incident.id);
    const { element, firstSeen, lastSeen } = await loadDates(incident.id, ENTITY_TYPE_INCIDENT);
    expect(element.severity).toBe('high');
    expect(firstSeen).toBe(FIRST_SEEN);
    expect(lastSeen).toBe(LAST_SEEN);
  });

  it.each(DATED_TYPES)('should keep the dates of an existing $type when the input has no dates', async ({ type, add }) => {
    const name = `Upsert limit dates ${type} ${Date.now()}`;
    const created = await add(testContext, ADMIN_USER, { name, created: CREATED, first_seen: FIRST_SEEN, last_seen: LAST_SEEN });
    createdIds.push({ id: created.id, type });
    const before = await loadDates(created.id, type);
    const upserted = await add(testContext, ADMIN_USER, { name, created: CREATED });
    expect(upserted.id).toBe(created.id);
    const after = await loadDates(created.id, type);
    expect(after.firstSeen).toBe(FIRST_SEEN);
    expect(after.lastSeen).toBe(LAST_SEEN);
    // Nothing else changed in the input: the upsert writes nothing
    expect(after.element.updated_at).toEqual(before.element.updated_at);
  });

  it('should keep the dates when the input carries the sentinels explicitly', async () => {
    const name = `Upsert limit dates explicit sentinels ${Date.now()}`;
    const campaign = await addCampaign(testContext, ADMIN_USER, { name, first_seen: FIRST_SEEN, last_seen: LAST_SEEN });
    createdIds.push({ id: campaign.id, type: ENTITY_TYPE_CAMPAIGN });
    await addCampaign(testContext, ADMIN_USER, { name, first_seen: FROM_START_STR, last_seen: UNTIL_END_STR });
    const { firstSeen, lastSeen } = await loadDates(campaign.id, ENTITY_TYPE_CAMPAIGN);
    expect(firstSeen).toBe(FIRST_SEEN);
    expect(lastSeen).toBe(LAST_SEEN);
  });

  it('should still update the dates when the input carries real dates', async () => {
    const name = `Upsert limit dates real dates ${Date.now()}`;
    const malware = await addMalware(testContext, ADMIN_USER, { name, first_seen: FIRST_SEEN, last_seen: LAST_SEEN });
    createdIds.push({ id: malware.id, type: ENTITY_TYPE_MALWARE });
    const newFirstSeen = '2026-09-01T00:00:00.000Z';
    const newLastSeen = '2026-11-10T00:00:00.000Z';
    await addMalware(testContext, ADMIN_USER, { name, first_seen: newFirstSeen, last_seen: newLastSeen });
    const { firstSeen, lastSeen } = await loadDates(malware.id, ENTITY_TYPE_MALWARE);
    expect(firstSeen).toBe(newFirstSeen);
    expect(lastSeen).toBe(newLastSeen);
  });

  it('should store the sentinels when an entity is created without dates', async () => {
    const name = `Upsert limit dates creation ${Date.now()}`;
    const intrusionSet = await addIntrusionSet(testContext, ADMIN_USER, { name });
    createdIds.push({ id: intrusionSet.id, type: ENTITY_TYPE_INTRUSION_SET });
    const { firstSeen, lastSeen } = await loadDates(intrusionSet.id, ENTITY_TYPE_INTRUSION_SET);
    expect(firstSeen).toBe(FROM_START_STR);
    expect(lastSeen).toBe(UNTIL_END_STR);
  });

  it('should keep the full replace of a synchronized upsert', async () => {
    // A synchronized upsert (synchronized-upsert header) mirrors the source: a source without dates resets them
    const name = `Upsert limit dates synchronized ${Date.now()}`;
    const group = await addThreatActorGroup(testContext, ADMIN_USER, { name, first_seen: FIRST_SEEN, last_seen: LAST_SEEN });
    createdIds.push({ id: group.id, type: ENTITY_TYPE_THREAT_ACTOR_GROUP });
    const synchronizedContext = { ...testContext, synchronizedUpsert: true } as AuthContext;
    await addThreatActorGroup(synchronizedContext, ADMIN_USER, { name });
    const { firstSeen, lastSeen } = await loadDates(group.id, ENTITY_TYPE_THREAT_ACTOR_GROUP);
    expect(firstSeen).toBe(FROM_START_STR);
    expect(lastSeen).toBe(UNTIL_END_STR);
  });
});
