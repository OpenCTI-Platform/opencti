import useVocabularyCategory from './useVocabularyCategory';
import useAuth from './useAuth';

const ignoredAttributes = [
  'id',
  'parent_types',
  'base_type',
  'internal_id',
  'standard_id',
  'x_opencti_description',
  'x_opencti_stix_ids',
  'x_opencti_files',
  'entity_type',
  'spec_version',
  'extensions',
  'created',
  'modified',
  'created_at',
  'x_opencti_score',
  'updated_at',
  'observable_value',
  'indicators',
  'importFiles',
  'startup_info',
  'creator_id',
];

const workbenchAttributes = [
  'name',
  'description',
  'case_type',
  'pattern',
  'x_opencti_description',
  'x_opencti_reliability',
  'first_seen',
  'last_seen',
  'start_time',
  'stop_time',
  'published',
  'content',
  'context',
];

const ignoredAttributesInFeeds = [
  'x_opencti_stix_ids',
  'spec_version',
  'extensions',
  'importFiles',
];

const ignoredAttributesInDashboards = [
  'spec_version',
  'extensions',
  'importFiles',
  'x_opencti_graph_data',
  'x_opencti_workflow_id',
  'x_opencti_stix_ids',
  'x_opencti_files',
  'creator',
  'created',
  'created_at',
  'modified',
  'updated_at',
  'internal_id',
  'standard_id',
  'published',
  'content',
  'content_mapping',
];

// TODO check the attribute type from backend
const dateAttributes = [
  'ctime',
  'mtime',
  'atime',
  'attribute_date',
  'validity_not_before',
  'validity_not_after',
  'private_key_usage_period_not_before',
  'private_key_usage_period_not_after',
  'start',
  'end',
  'created_time',
  'modified_time',
  'account_created',
  'account_expires',
  'credential_last_changed',
  'account_first_login',
  'account_last_login',
  'expiration_date',
  'publication_date',
  'first_seen',
  'last_seen',
  'published',
  'start_time',
  'stop_time',
  'transaction_date',
];

const numberAttributes = [
  'x_opencti_score',
  'confidence',
  'number',
  'src_port',
  'dst_port',
  'src_byte_count',
  'dst_byte_count',
  'src_packets',
  'dst_packets',
  'pid',
  'size',
  'number_of_subkeys',
  'subject_public_key_exponent',
  'cvv',
  'asset_value',
  'transaction_value',
];

const booleanAttributes = [
  'x_opencti_detection',
  'is_self_signed',
  'is_multipart',
  'is_hidden',
  'is_active',
  'is_disabled',
  'is_privileged',
  'is_service_account',
  'can_escalate_privs',
  'aslr_enabled',
  'dep_enabled',
];

const multipleAttributes = [
  'x_opencti_additional_names',
  'protocols',
  'descriptions',
];

const markdownAttributes = ['description', 'x_opencti_description'];

const htmlAttributes = ['content'];

const typesWithoutName = ['Observed-Data'];

const typesContainers = [
  'report',
  'note',
  'case',
  'opinion',
  'observed-data',
  'grouping',
  'feedback',
  'x-opencti-case-incident',
  'case-incident',
  'x-opencti-case-rfi',
  'case-rfi',
  'x-opencti-case-rft',
  'case-rft',
  'x-opencti-task',
  'task',
];

export const containerTypes = [
  'Report',
  'Grouping',
  'Note',
  'Feedback',
  'Case-Incident',
  'Case-Rfi',
  'Case-Rft',
  'Task',
  'Opinion',
  'Observed-Data',
];

const useAttributes = () => {
  const vocabularies = useVocabularyCategory();
  const { sdos, scos } = useAuth().schema;
  const stixDomainObjectTypes = sdos.map((sdo) => sdo.id);
  const stixCyberObservableTypes = scos.map((sco) => sco.id);
  const stixCoreObjectTypes = stixDomainObjectTypes.concat(stixCyberObservableTypes);
  return {
    ignoredAttributes,
    workbenchAttributes,
    ignoredAttributesInFeeds,
    ignoredAttributesInDashboards,
    dateAttributes,
    numberAttributes,
    booleanAttributes,
    multipleAttributes,
    markdownAttributes,
    htmlAttributes,
    stixDomainObjectTypes,
    stixCyberObservableTypes,
    stixCoreObjectTypes,
    typesWithoutName,
    typesContainers,
    vocabularyAttributes: vocabularies.fields,
    containerTypes,
  };
};

export default useAttributes;
