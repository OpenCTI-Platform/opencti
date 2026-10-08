import { buildStixObject } from '../../database/stix-2-1-converter';
import { cleanObject } from '../../database/stix-converter-utils';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type {
  StixCurationPolicy,
  StixCurationProposal,
  StixKnowledgeHealthSnapshot,
  StixMergeRecord,
  StoreEntityCurationPolicy,
  StoreEntityCurationProposal,
  StoreEntityKnowledgeHealthSnapshot,
  StoreEntityMergeRecord,
} from './curation-types';

const internalExtension = (stixObject: ReturnType<typeof buildStixObject>) => cleanObject({
  ...stixObject.extensions[STIX_EXT_OCTI],
  extension_type: 'new-sdo' as const,
});

export const convertCurationProposalToStix = (instance: StoreEntityCurationProposal): StixCurationProposal => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    proposal_kind: instance.proposal_kind,
    proposal_status: instance.proposal_status,
    confidence_score: instance.confidence_score,
    subject_ids: instance.subject_ids,
    extensions: { [STIX_EXT_OCTI]: internalExtension(stixObject) },
  } as StixCurationProposal;
};

export const convertMergeRecordToStix = (instance: StoreEntityMergeRecord): StixMergeRecord => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    merge_target_id: instance.merge_target_id,
    merge_source_ids: instance.merge_source_ids,
    merge_status: instance.merge_status,
    extensions: { [STIX_EXT_OCTI]: internalExtension(stixObject) },
  } as StixMergeRecord;
};

export const convertCurationPolicyToStix = (instance: StoreEntityCurationPolicy): StixCurationPolicy => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    extensions: { [STIX_EXT_OCTI]: internalExtension(stixObject) },
  };
};

export const convertKnowledgeHealthSnapshotToStix = (instance: StoreEntityKnowledgeHealthSnapshot): StixKnowledgeHealthSnapshot => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    snapshot_date: instance.snapshot_date,
    health_score: instance.health_score,
    extensions: { [STIX_EXT_OCTI]: internalExtension(stixObject) },
  };
};
