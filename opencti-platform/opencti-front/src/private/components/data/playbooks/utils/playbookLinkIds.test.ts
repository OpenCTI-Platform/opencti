import { describe, expect, it } from 'vitest';
import { insertedLinkIds, linkIdFromDefinition } from './playbookLinkIds';

const definition = JSON.stringify({
  nodes: [{ id: 'listen' }, { id: 'match' }, { id: 'share' }, { id: 'other' }],
  links: [
    { id: 'l1', from: { id: 'listen', port: 'out' }, to: { id: 'match' } },
    { id: 'f3a9c2e0-uuid', from: { id: 'match', port: 'out' }, to: { id: 'share' } },
    { id: 'l3', from: { id: 'match', port: 'no-match' }, to: { id: 'other' } },
  ],
});

describe('linkIdFromDefinition', () => {
  it('answers the id the server stored for the link from the parent port to the new step', () => {
    expect(linkIdFromDefinition(definition, 'match', 'out', 'share')).toBe('f3a9c2e0-uuid');
  });

  it('never answers an id made up from the endpoints', () => {
    expect(linkIdFromDefinition(definition, 'match', 'out', 'share')).not.toBe('match-out-share');
  });

  it('matches the port, not only the parent', () => {
    expect(linkIdFromDefinition(definition, 'match', 'no-match', 'share')).toBeUndefined();
  });

  it('answers undefined on an empty or unreadable definition', () => {
    expect(linkIdFromDefinition(null, 'match', 'out', 'share')).toBeUndefined();
    expect(linkIdFromDefinition('{', 'match', 'out', 'share')).toBeUndefined();
    expect(linkIdFromDefinition('{}', 'match', 'out', 'share')).toBeUndefined();
  });
});

describe('insertedLinkIds', () => {
  it('gives the returned id to parent -> new step and keeps the former id on new step -> child, as playbookInsertNode stores them', () => {
    expect(insertedLinkIds('l1', { linkId: 'new-uuid' })).toEqual({ toNewStep: 'new-uuid', fromNewStep: 'l1' });
  });
});
