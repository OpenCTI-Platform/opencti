import useVocabularyCategory from './useVocabularyCategory';

// TODO remove export when every usage is pure Function and use the hook
export const ignoredAttributes = [
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

export const workbenchAttributes = [
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

export const ignoredAttributesInFeeds = [
  'x_opencti_stix_ids',
  'spec_version',
  'extensions',
  'importFiles',
];

export const ignoredAttributesInDashboards = [
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

export const dateAttributes = [
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
];

export const numberAttributes = [
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
];

export const booleanAttributes = [
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

export const multipleAttributes = [
  'x_opencti_additional_names',
  'protocols',
  'descriptions',
];

export const markdownAttributes = ['description', 'x_opencti_description'];

export const htmlAttributes = ['content'];

export const typesWithOpenCTIAliases = [
  'Course-Of-Action',
  'Identity',
  'Individual',
  'Organization',
  'Sector',
  'Position',
  'Administrative-Area',
  'Location',
  'City',
  'Country',
  'Region',
  'Event',
  'Channel',
  'Narrative',
  'Threat-Actor-Individual',
  'Threat-Actor-Group',
];

export const typesWithoutAliases = [
  'Indicator',
  'Vulnerability',
  'Language',
  'Grouping',
  'Report',
];

// TODO replace this by a proper hook using backend information
export const stixDomainObjectTypes = [
  'Stix-Domain-Object',
  'Threat-Actor',
  'Threat-Actor-Individual',
  'Threat-Actor-Group',
  'Intrusion-Set',
  'Campaign',
  'Incident',
  'Malware',
  'Tool',
  'Attack-Pattern',
  'Course-Of-Action',
  'Data-Component',
  'Data-Source',
  'Organization',
  'Sector',
  'Position',
  'Administrative-Area',
  'Location',
  'City',
  'Country',
  'Region',
  'Event',
  'Channel',
  'Narrative',
  'Indicator',
  'Vulnerability',
  'Language',
  'Grouping',
  'Report',
  'Narrative',
  'Channel',
];

export const stixCyberObservableTypes = [
  'Stix-Cyber-Observable',
  'Autonomous-System',
  'Directory',
  'Domain-Name',
  'Email-Addr',
  'Email-Message',
  'Email-Mime-Part-Type',
  'StixFile',
  'X509-Certificate',
  'IPv4-Addr',
  'IPv6-Addr',
  'Mac-Addr',
  'Mutex',
  'Network-Traffic',
  'Process',
  'Software',
  'Url',
  'User-Account',
  'Windows-Registry-Key',
  'Windows-Registry-Value-Type',
  'Cryptographic-Key',
  'Cryptocurrency-Wallet',
  'Hostname',
  'Text',
  'User-Agent',
  'Bank-Account',
  'Phone-Number',
  'Payment-Card',
  'Media-Content',
];

export const typesWithoutName = ['Observed-Data'];

export const typesContainers = [
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

const useAttributes = () => {
  const vocabularies = useVocabularyCategory();
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
    typesWithOpenCTIAliases,
    typesWithoutAliases,
    stixDomainObjectTypes,
    stixCyberObservableTypes,
    typesWithoutName,
    typesContainers,
    vocabularyAttributes: vocabularies.fields,
  };
};

export default useAttributes;
