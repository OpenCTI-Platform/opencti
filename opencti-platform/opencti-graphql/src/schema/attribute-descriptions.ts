import { ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_THREAT_ACTOR_GROUP } from './stixDomainObject';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../modules/threatActorIndividual/threatActorIndividual-types';
import { ENTITY_TYPE_EVENT } from '../modules/event/event-types';

// Descriptions of the attributes and refs, exposed by schemaAttributes so that an API client
// (an XTM One agent for instance) picks the right field and fills it with the right value.
// name, description, first_seen… are redeclared in each type definition: a description is
// written once per attribute name here, and overridden for a type when its meaning differs.
// A vocabulary field names its category: its values are listed by the vocabularies query.

export const ATTRIBUTE_DESCRIPTIONS: Record<string, string> = {
  // -- Common --
  name: 'Name of the entity.',
  description: 'Description of the entity, in Markdown.',
  confidence: 'Confidence in the correctness of the data, from 0 (none) to 100 (full).',
  created: 'Date when the entity was originally created by its author, in ISO 8601. Defaults to the creation date in the platform.',
  x_opencti_aliases: 'Alternative names of the entity.',
  x_opencti_score: 'Score assessing how malicious or important the entity is, from 0 to 100.',
  x_opencti_reliability: 'Reliability of the source, from the reliability_ov vocabulary (A - Completely reliable to F - Reliability cannot be judged).',
  authorized_members_activation_date: 'Date when access to the entity was restricted to its authorized members. Set by the platform.',
  // -- Activity --
  first_seen: 'Date when the entity was first seen active, in ISO 8601.',
  last_seen: 'Date when the entity was last seen active, in ISO 8601.',
  objective: 'Main goal of the campaign or incident.',
  goals: 'High-level goals of the threat (e.g. steal credit card numbers).',
  resource_level: 'Organizational level the threat works at, from the attack_resource_level_ov vocabulary (e.g. individual, organization, government).',
  primary_motivation: 'Main reason behind the threat, from the attack_motivation_ov vocabulary (e.g. personal-gain, ideology).',
  secondary_motivations: 'Other reasons behind the threat, from the attack_motivation_ov vocabulary.',
  personal_motivations: 'Personal reasons of the threat actor, from the attack_motivation_ov vocabulary.',
  sophistication: 'Skill level of the threat actor (e.g. minimal, expert, strategic).',
  threat_actor_types: 'Types of the threat actor (e.g. nation-state, crime-syndicate, activist).',
  // -- Identity and location --
  contact_information: 'Contact information (email, phone…) of the identity.',
  roles: 'Roles the identity plays (e.g. CEO, analyst).',
  x_opencti_organization_type: 'Type of the organization, from the organization_type_ov vocabulary (e.g. vendor, partner, csirt).',
  security_platform_type: 'Type of the security platform, from the security_platform_type_ov vocabulary (e.g. EDR, SIEM).',
  latitude: 'Latitude of the location, in decimal degrees.',
  longitude: 'Longitude of the location, in decimal degrees.',
  street_address: 'Street address of the position.',
  postal_code: 'Postal code of the position.',
  // -- Threat actor individual --
  date_of_birth: 'Date of birth of the threat actor, in ISO 8601.',
  gender: 'Gender of the threat actor, from the gender_ov vocabulary.',
  marital_status: 'Marital status of the threat actor, from the marital_status_ov vocabulary.',
  job_title: 'Job title of the threat actor.',
  eye_color: 'Eye color of the threat actor, from the eye_color_ov vocabulary.',
  hair_color: 'Hair color of the threat actor, from the hair_color_ov vocabulary.',
  height: 'Heights of the threat actor over time: each has a measure in centimeters and a date_seen.',
  weight: 'Weights of the threat actor over time: each has a measure in kilograms and a date_seen.',
  // -- Arsenal --
  malware_types: 'Types of the malware, from the malware_type_ov vocabulary (e.g. ransomware, backdoor, trojan).',
  is_family: 'Whether the malware is a family (true) or a single instance (false).',
  architecture_execution_envs: 'Processor architectures the malware runs on, from the processor_architecture_ov vocabulary (e.g. x86, arm).',
  implementation_languages: 'Programming languages the malware is written in, from the implementation_language_ov vocabulary.',
  capabilities: 'Capabilities of the malware, from the malware_capabilities_ov vocabulary (e.g. exfiltrates-data, persists-after-system-reboot).',
  tool_types: 'Types of the tool, from the tool_types_ov vocabulary (e.g. remote-access, credential-exploitation).',
  tool_version: 'Version of the tool.',
  infrastructure_types: 'Types of the infrastructure, from the infrastructure_type_ov vocabulary (e.g. botnet, command-and-control).',
  channel_types: 'Types of the channel, from the channel_types_ov vocabulary (e.g. Twitter, Facebook).',
  narrative_types: 'Types of the narrative.',
  event_types: 'Types of the event, from the event_type_ov vocabulary (e.g. conference, sport-competition).',
  // Also the validity period of the relationships, which share these names
  start_time: 'Date from which the relationship is valid, in ISO 8601.',
  stop_time: 'Date until which the relationship is valid, in ISO 8601.',
  // -- Techniques --
  x_mitre_id: 'MITRE ATT&CK identifier (e.g. T1059 for a technique, M1036 for a mitigation).',
  x_mitre_platforms: 'Platforms concerned, from the platforms_ov vocabulary (e.g. windows, linux, macos).',
  x_mitre_permissions_required: 'Permissions needed to use the technique, from the permissions_ov vocabulary (e.g. User, Administrator).',
  x_mitre_detection: 'How to detect the technique.',
  collection_layers: 'Layers the data source collects from, from the collection_layers_ov vocabulary (e.g. host, network, cloud).',
  // -- Indicator --
  pattern: 'Detection pattern of the indicator, written in the language given by pattern_type (e.g. [ipv4-addr:value = \'198.51.100.1\'] in STIX).',
  pattern_type: 'Language of the pattern, from the pattern_type_ov vocabulary (e.g. stix, yara, sigma, snort).',
  indicator_types: 'Types of the indicator, from the indicator_type_ov vocabulary (e.g. malicious-activity, anomalous-activity).',
  valid_from: 'Date from which the indicator is valid, in ISO 8601.',
  valid_until: 'Date until which the indicator is valid, in ISO 8601.',
  x_opencti_main_observable_type: 'Type of the main observable the pattern detects (e.g. IPv4-Addr, Domain-Name, StixFile).',
  decay_exclusion_applied_rule: 'Decay exclusion rule applied to the indicator. Set by the platform.',
  // -- Incident --
  incident_type: 'Type of the incident, from the incident_type_ov vocabulary (e.g. data-leak, ransomware, phishing).',
  severity: 'Severity, from the incident_severity_ov or case_severity_ov vocabulary (e.g. low, medium, high, critical).',
  source: 'Source that reported the incident.',
  // -- Vulnerability --
  x_opencti_cvss_base_score: 'CVSS v3 base score, from 0 to 10.',
  x_opencti_cvss_vector_string: 'CVSS v3 vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).',
  x_opencti_cvss_v2_base_score: 'CVSS v2 base score, from 0 to 10.',
  x_opencti_cvss_v2_vector_string: 'CVSS v2 vector string (e.g. AV:N/AC:L/Au:N/C:P/I:P/A:P).',
  x_opencti_cvss_v4_base_score: 'CVSS v4 base score, from 0 to 10.',
  x_opencti_cvss_v4_vector_string: 'CVSS v4 vector string (e.g. CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N).',
  x_opencti_epss_score: 'EPSS score: probability that the vulnerability is exploited in the next 30 days, from 0 to 1.',
  x_opencti_epss_percentile: 'EPSS percentile of the vulnerability among all scored ones, from 0 to 1.',
  x_opencti_cisa_kev: 'Whether the vulnerability is in the CISA Known Exploited Vulnerabilities catalog.',
  x_opencti_ssvc_exploitation: 'SSVC exploitation status: none, proof_of_concept or active.',
  x_opencti_ssvc_automatable: 'SSVC automatable: yes or no.',
  x_opencti_ssvc_technical_impact: 'SSVC technical impact: partial or total.',
  // -- Containers --
  content: 'Full content of the container, as rich text (HTML).',
  published: 'Date when the report was published, in ISO 8601.',
  report_types: 'Types of the report, from the report_types_ov vocabulary (e.g. threat-report, internal-report).',
  context: 'Context of the grouping, from the grouping_context_ov vocabulary (e.g. suspicious-activity, malware-analysis).',
  attribute_abstract: 'Short summary of the note.',
  authors: 'Names of the authors of the note or opinion.',
  note_types: 'Types of the note, from the note_types_ov vocabulary (e.g. analysis, assessment).',
  likelihood: 'Likelihood that the note is true, from 0 to 100.',
  opinion: 'Agreement with the information, from the opinion_ov vocabulary (strongly-disagree to strongly-agree).',
  explanation: 'Explanation of the opinion.',
  first_observed: 'Start of the observation window, in ISO 8601.',
  last_observed: 'End of the observation window, in ISO 8601.',
  number_observed: 'Number of times the data was observed in the window.',
  number_seen: 'Number of times the objects were seen.',
  max_distinct_count: 'Highest number of distinct values observed.',
  // -- Cases and tasks --
  priority: 'Priority of the case, from the case_priority_ov vocabulary (e.g. P1, P2, P3, P4).',
  response_types: 'Types of response to the incident, from the incident_response_types_ov vocabulary (e.g. ransomware, data-leak).',
  information_types: 'Types of information requested, from the request_for_information_types_ov vocabulary.',
  takedown_types: 'Types of takedown requested, from the request_for_takedown_types_ov vocabulary (e.g. phishing, brand-abuse).',
  x_opencti_request_access: 'Request for access to restricted knowledge, as JSON. Set by the platform.',
  rating: 'Rating given in the feedback, from 1 to 5.',
  due_date: 'Date when the task is due, in ISO 8601.',
  // -- Malware analysis --
  product: 'Name of the product that ran the analysis (e.g. a sandbox).',
  version: 'Version of the analysis product.',
  configuration_version: 'Version of the configuration used for the analysis.',
  modules: 'Modules of the analysis product used for the analysis.',
  analysis_engine_version: 'Version of the analysis engine.',
  analysis_definition_version: 'Version of the definitions (signatures) used by the analysis engine.',
  submitted: 'Date when the sample was submitted for analysis, in ISO 8601.',
  analysis_started: 'Date when the analysis started, in ISO 8601.',
  analysis_ended: 'Date when the analysis ended, in ISO 8601.',
  result_name: 'Classification name given by the analysis (e.g. a malware family).',
  result: 'Verdict of the analysis, from the malware_result_ov vocabulary (malicious, suspicious, benign, unknown).',
  // -- Security coverage --
  coverage_information: 'Coverage scores: each has a coverage_name (coverage_ov vocabulary) and a coverage_score in percent.',
  coverage_last_result: 'Date of the last coverage result, in ISO 8601.',
  coverage_valid_from: 'Date from which the coverage is valid, in ISO 8601.',
  coverage_valid_to: 'Date until which the coverage is valid, in ISO 8601.',
  periodicity: 'How often the coverage is assessed, or how long a manual coverage is valid, as an ISO 8601 duration (e.g. P1D).',
  duration: 'Duration of a coverage assessment, as an ISO 8601 duration (e.g. PT1H).',
  type_affinity: 'Type of asset the coverage targets (e.g. ENDPOINT).',
  platforms_affinity: 'Platforms the coverage targets, from the platforms_ov vocabulary (e.g. windows, linux).',
  auto_enrichment_disable: 'Whether the enrichment connectors are prevented from assessing the coverage (manual coverage).',
  external_uri: 'Link to the coverage in the external tool that produced it.',
  // -- Refs --
  createdBy: 'Author of the entity: an identity (organization, individual, sector or system).',
  objectMarking: 'Marking definitions (e.g. TLP:AMBER) restricting who can see the entity.',
  objectLabel: 'Labels tagging the entity.',
  externalReferences: 'External references (source URL, report…) of the entity.',
  objectOrganization: 'Organizations the entity is shared with.',
  objectAssignee: 'Users assigned to the entity.',
  objectParticipant: 'Users participating in the entity.',
  killChainPhases: 'Kill chain phases (e.g. MITRE ATT&CK tactics) the entity belongs to.',
  objects: 'Entities and relationships contained in the container.',
  samples: 'Files or artifacts that are samples of the malware.',
  operatingSystems: 'Operating systems the malware runs on, as Software observables.',
  analysisSample: 'Sample (file, artifact, network traffic or domain) analyzed.',
  analysisSco: 'Observables found by the analysis.',
  operatingSystem: 'Operating system of the analysis environment, as a Software observable.',
  hostVm: 'Virtual machine hosting the analysis, as a Software observable.',
  installedSoftware: 'Software installed in the analysis environment.',
  bornIn: 'Country where the threat actor was born.',
  ethnicity: 'Country of the ethnicity of the threat actor.',
  dataSource: 'Data source the data component belongs to.',
  objectCovered: 'Entity (intrusion set, campaign, incident or report) whose coverage is assessed.',
  resultOf: 'Security coverage results.',
};

// Overrides for the types where an attribute does not mean the same as elsewhere
export const ATTRIBUTE_DESCRIPTIONS_BY_TYPE: Record<string, Record<string, string>> = {
  [ENTITY_TYPE_EVENT]: {
    start_time: 'Date when the event started, in ISO 8601.',
    stop_time: 'Date when the event ended, in ISO 8601.',
  },
  [ENTITY_TYPE_CONTAINER_NOTE]: {
    content: 'Text of the note, in Markdown.',
  },
  [ENTITY_TYPE_THREAT_ACTOR_GROUP]: {
    roles: 'Roles of the threat actor group, from the threat_actor_group_role_ov vocabulary (e.g. agent, director, sponsor).',
  },
  [ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL]: {
    roles: 'Roles of the threat actor, from the threat_actor_individual_role_ov vocabulary (e.g. agent, director, sponsor).',
  },
};

// Resolution order: the description written in the definition, then the override of the type, then the dictionary
export const resolveAttributeDescription = (entityType: string, attribute: { name: string; description?: string }): string | null => {
  return attribute.description
    ?? ATTRIBUTE_DESCRIPTIONS_BY_TYPE[entityType]?.[attribute.name]
    ?? ATTRIBUTE_DESCRIPTIONS[attribute.name]
    ?? null;
};
