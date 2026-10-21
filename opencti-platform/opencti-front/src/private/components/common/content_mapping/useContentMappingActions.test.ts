import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import useContentMappingActions from './useContentMappingActions';
import { decodeMapping, decodeReview, EMPTY_REVIEW, MappableEntity } from './contentMappingModel';

const calls = vi.hoisted(() => [] as { name: string; variables: Record<string, unknown> }[]);
vi.mock('../../../../relay/environment', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../relay/environment')>(),
  commitMutation: ({ mutation, variables, onCompleted }: { mutation: { params: { name: string } }; variables: Record<string, unknown>; onCompleted: (r: unknown) => void }) => {
    const name = mutation.params.name.replace('contentMappingQueries', '').replace('Mutation', '');
    calls.push({ name, variables });
    const created = { id: 'created-id', standard_id: 'ipv4-addr--new', entity_type: 'IPv4-Addr', representative: { main: '45.77.120.14' } };
    onCompleted({ stixCyberObservableAdd: created, stixDomainObjectAdd: { ...created, entity_type: 'Malware' } });
  },
}));

const apt41: MappableEntity = { id: 'apt41-id', standard_id: 'intrusion-set--1', entity_type: 'Intrusion-Set', representative: { main: 'APT41' } };

const setup = (objectIds: string[] = []) => {
  const refresh = vi.fn();
  const { result } = renderHook(() => useContentMappingActions({
    id: 'report-id', objectIds: new Set(objectIds), mapping: {}, review: EMPTY_REVIEW, serverVersion: '|', createdById: 'author-id',
  }, refresh));
  return { actions: result.current, refresh };
};

const lastPatch = () => {
  const patch = [...calls].reverse().find((c) => c.name === 'FieldPatch')!;
  const [mapping, review] = patch.variables.input as { key: string; value: string[] }[];
  return { mapping: decodeMapping(mapping.value[0]), review: decodeReview(review.value[0]) };
};

describe('useContentMappingActions', () => {
  beforeEach(() => {
    calls.length = 0;
  });

  it('should add an existing object to the container before mapping it', async () => {
    const { actions, refresh } = setup();
    await actions.mapExisting('APT41', apt41, 'main');
    expect(calls.map((c) => c.name)).toEqual(['RelationsAdd', 'FieldPatch']);
    expect(calls[0].variables).toEqual({ id: 'report-id', toIds: ['apt41-id'] });
    expect(lastPatch().mapping).toEqual({ apt41: 'intrusion-set--1' });
    expect(lastPatch().review.sources).toEqual({ apt41: 'main' });
    expect(refresh).toHaveBeenCalled();
  });

  it('should not add an object that is already in the container', async () => {
    const { actions } = setup(['apt41-id']);
    await actions.mapExisting('APT41', apt41, 'main');
    expect(calls.map((c) => c.name)).toEqual(['FieldPatch']);
  });

  it('should create an observable with the refanged value, map it, and undo everything', async () => {
    const { actions } = setup();
    const { undo } = await actions.createAndMap('45[.]77[.]120[.]14', 'IPv4-Addr', 'file-1');
    expect(calls[0]).toEqual({ name: 'ObservableAdd', variables: expect.objectContaining({ type: 'IPv4-Addr', createdBy: 'author-id', IPv4Addr: { value: '45.77.120.14' } }) });
    expect(lastPatch().mapping).toEqual({ '45[.]77[.]120[.]14': 'ipv4-addr--new' });
    calls.length = 0;
    await undo();
    expect(calls.map((c) => c.name)).toEqual(['FieldPatch', 'Delete']);
    expect(lastPatch().mapping).toEqual({});
  });

  it('should create the new objects of a bulk validation with the enrichment', async () => {
    const { actions } = setup(['apt41-id']);
    const count = await actions.validate([
      { value: 'APT41', entity: apt41, entityType: 'Intrusion-Set', source: 'main' },
      { value: 'DeedRAT', entity: null, entityType: 'Malware', source: 'main' },
    ], { objectMarking: ['tlp-clear'], objectLabel: ['apt'], confidence: 75 });
    expect(count).toBe(2);
    expect(calls.find((c) => c.name === 'DomainObjectAdd')?.variables).toEqual({
      input: { type: 'Malware', name: 'DeedRAT', objectMarking: ['tlp-clear'], objectLabel: ['apt'], createdBy: 'author-id', confidence: 75 },
    });
    expect(lastPatch().mapping).toEqual({ apt41: 'intrusion-set--1', deedrat: 'ipv4-addr--new' });
  });

  it('should ignore and restore suggestions, and keep the chosen type', async () => {
    const { actions } = setup();
    await actions.ignore([{ key: 'frp', value: 'FRP', entityType: 'Tool', standardId: 'tool--1' }]);
    expect(lastPatch().review.ignored).toEqual({ frp: { value: 'FRP', entityType: 'Tool', standardId: 'tool--1' } });
    await actions.changeType('45.77.120.14', 'IPv4-Addr');
    expect(lastPatch().review.types).toEqual({ '45.77.120.14': 'IPv4-Addr' });
    await actions.restore(['frp']);
    expect(lastPatch().review.ignored).toEqual({});
    expect(lastPatch().review.types).toEqual({ '45.77.120.14': 'IPv4-Addr' });
  });
});
