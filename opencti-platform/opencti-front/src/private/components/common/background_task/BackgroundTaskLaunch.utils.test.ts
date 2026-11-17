import { describe, expect, it } from 'vitest';
import { confirmsOnlyAboveLimit } from './BackgroundTaskLaunch.utils';

const otherActionTypes = [
  'ADD',
  'COMPLETE_DELETE',
  'DELETE',
  'ENROLL_PLAYBOOK',
  'MERGE',
  'PROMOTE',
  'REMOVE',
  'REMOVE_AUTH_MEMBERS',
  'REMOVE_FROM_DRAFT',
  'REPLACE',
  'RESTORE',
  'RULE_ELEMENT_RESCAN',
  'SEND_EMAIL',
  'SHARE_MULTIPLE',
  'UNSHARE_MULTIPLE',
];

describe('Function: confirmsOnlyAboveLimit', () => {
  it('asks for a confirmation only above the limit for an enrichment', () => {
    expect(confirmsOnlyAboveLimit([{ type: 'ENRICHMENT' }])).toBe(true);
  });

  it.each(otherActionTypes)('always asks for a confirmation for %s', (type) => {
    expect(confirmsOnlyAboveLimit([{ type }])).toBe(false);
  });

  it('always asks for a confirmation when an enrichment comes with another action', () => {
    expect(confirmsOnlyAboveLimit([{ type: 'ENRICHMENT' }, { type: 'DELETE' }])).toBe(false);
  });

  it('always asks for a confirmation without actions', () => {
    expect(confirmsOnlyAboveLimit([])).toBe(false);
  });
});
