import { describe, expect, it } from 'vitest';
import { completeContextDataForEntity } from '../../../src/listener/UserActionListener';
import type { UserReadActionContextData } from '../../../src/listener/UserActionListener';
import type {BasicStoreCommon} from "../../../src/types/store";

describe('User Action listening', () => {
  it('should complete context data for entity', async () => {
    const data = {
      _id: 'id',
      id: 'id',
      internal_id: 'internal_id',
      _index: 'index',
      standard_id: 'report--123' as `${string}--${any}`,
      entity_type: 'Report',
      base_type: 'ENTITY' as ('ENTITY' | 'RELATION'),
      parent_types: ['Stix-Domain-Object', 'Stix-Core-Object'],
      spec_version: 'spec_version',
      created_at: '2024-12-12' as unknown as Date,
      updated_at: '2024-12-12' as unknown as Date,
      representative: { main: 'main', secondary: 'secondary' },
      creator_id: 'creator1_id',
      granted: ['orga1_id'],
      'object-marking': ['marking1_id', 'marking2_id'],
      'object-label': ['label1_id', 'label1_id'],
    };
    const contextData = {
      id: 'data_id',
      entity_name: 'data_name',
      entity_type: 'Report',
    };
    const completedContextData = completeContextDataForEntity(contextData, data as BasicStoreCommon) as UserReadActionContextData;
    expect(completedContextData.id).toEqual(contextData.id);
    expect(completedContextData.entity_type).toEqual(contextData.entity_type);
    expect(completedContextData.creator_ids?.length).toEqual(1);
    expect(completedContextData.creator_ids?.[0]).toEqual(data.creator_id);
    expect(completedContextData.granted_refs_ids?.[0]).toEqual(data.granted[0]);
    expect(completedContextData.object_marking_refs_ids?.length).toEqual(data['object-marking'].length);
    expect(completedContextData.created_by_ref_id).toBeUndefined();
    expect(completedContextData.labels_ids?.length).toEqual(data['object-label'].length);
  });
});
