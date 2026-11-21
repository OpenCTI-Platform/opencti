import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_DATA_COMPONENT,
  ENTITY_TYPE_DATA_SOURCE,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_TOOL,
  isStixDomainObject,
} from './stixDomainObject';
import { isStixCoreRelationship } from './stixCoreRelationship';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../modules/securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../modules/threatActorIndividual/threatActorIndividual-types';
import { ENTITY_TYPE_CHANNEL } from '../modules/channel/channel-types';
import { ENTITY_TYPE_NARRATIVE } from '../modules/narrative/narrative-types';
import { ENTITY_TYPE_EVENT } from '../modules/event/event-types';
import { ENTITY_TYPE_INDICATOR } from '../modules/indicator/indicator-types';
import { ENTITY_TYPE_VULNERABILITY } from '../modules/vulnerability/vulnerability-types';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../modules/grouping/grouping-types';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../modules/case/case-incident/case-incident-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../modules/case/case-rfi/case-rfi-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFT } from '../modules/case/case-rft/case-rft-types';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from '../modules/case/feedback/feedback-types';
import { ENTITY_TYPE_CONTAINER_TASK } from '../modules/task/task-types';
import { ENTITY_TYPE_MALWARE_ANALYSIS } from '../modules/malwareAnalysis/malwareAnalysis-types';
import { ENTITY_TYPE_SECURITY_COVERAGE } from '../modules/securityCoverage/securityCoverage-types';
import { ENTITY_TYPE_SECURITY_COVERAGE_RESULT } from '../modules/securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { isStixSightingRelationship, STIX_SIGHTING_RELATIONSHIP } from './stixSightingRelationship';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_LABEL, ENTITY_TYPE_MARKING_DEFINITION, isStixMetaObject } from './stixMetaObject';
import { ENTITY_TYPE_VOCABULARY } from '../modules/vocabulary/vocabulary-types';
import {
  ENTITY_AUTONOMOUS_SYSTEM,
  ENTITY_BANK_ACCOUNT,
  ENTITY_DIRECTORY,
  ENTITY_EMAIL_ADDR,
  ENTITY_EMAIL_MESSAGE,
  ENTITY_EMAIL_MIME_PART_TYPE,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE,
  ENTITY_MEDIA_CONTENT,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PAYMENT_CARD,
  ENTITY_PERSONA,
  ENTITY_PROCESS,
  ENTITY_SOFTWARE,
  ENTITY_SSH_KEY,
  ENTITY_USER_ACCOUNT,
  ENTITY_WINDOWS_REGISTRY_KEY,
  ENTITY_WINDOWS_REGISTRY_VALUE_TYPE,
  isStixCyberObservable,
} from './stixCyberObservable';

// Descriptions of the attributes and refs, exposed by schemaAttributes so that an API client
// (an XTM One agent for instance) picks the right field and fills it with the right value.
// name, description, first_seen… are redeclared in each type definition: a name shared by
// several types is described once in ATTRIBUTE_DESCRIPTIONS, and overridden for a type when its
// meaning differs there. A name used by a single type is described in ATTRIBUTE_DESCRIPTIONS_BY_TYPE:
// a new attribute reusing it elsewhere then gets no description, and the completeness test asks
// for one, instead of silently inheriting a text written for another type.
// A vocabulary field names its category: its values are listed by the vocabularies query.

export const ATTRIBUTE_DESCRIPTIONS: Record<string, string> = {
  // -- Common --
  name: 'Name of the entity.',
  description: 'Description of the entity, in Markdown.',
  confidence: 'Confidence in the correctness of the data, from 0 (none) to 100 (full). Capped at the max confidence level of the user, which is also the default.',
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
  sophistication: 'Skill level of the threat actor, from the threat_actor_group_sophistication_ov or threat_actor_individual_sophistication_ov vocabulary (e.g. minimal, expert, strategic).',
  threat_actor_types: 'Types of the threat actor, from the threat_actor_group_type_ov or threat_actor_individual_type_ov vocabulary (e.g. nation-state, crime-syndicate, activist).',
  // -- Identity and location --
  contact_information: 'Contact information (email, phone…) of the identity.',
  roles: 'Roles the identity plays (e.g. CEO, analyst).',
  latitude: 'Latitude of the location, in decimal degrees.',
  longitude: 'Longitude of the location, in decimal degrees.',
  // -- Relationships --
  start_time: 'Date from which the relationship is valid, in ISO 8601.',
  stop_time: 'Date until which the relationship is valid, in ISO 8601.',
  // -- Techniques --
  x_mitre_id: 'MITRE ATT&CK identifier (e.g. T1059 for a technique, M1036 for a mitigation).',
  x_mitre_platforms: 'Platforms concerned, from the platforms_ov vocabulary (e.g. windows, linux, macos).',
  // -- Incidents and cases --
  severity: 'Severity, from the incident_severity_ov or case_severity_ov vocabulary (e.g. low, medium, high, critical).',
  // -- Containers --
  content: 'Full content of the container, as rich text (HTML).',
  authors: 'Names of the authors of the note or opinion.',
  priority: 'Priority of the case, from the case_priority_ov vocabulary (e.g. P1, P2, P3, P4).',
  // -- Security coverage --
  coverage_information: 'Coverage scores: each has a coverage_name (coverage_ov vocabulary) and a coverage_score in percent.',
  coverage_last_result: 'Date of the last coverage result, in ISO 8601.',
  coverage_valid_from: 'Date from which the coverage is valid, in ISO 8601.',
  coverage_valid_to: 'Date until which the coverage is valid, in ISO 8601.',
  external_uri: 'Link to the coverage in the external tool that produced it.',
  // -- Observables --
  x_opencti_description: 'Description of the observable.',
  value: 'Value of the observable, in the format of its type (e.g. 198.51.100.7 for an IPv4-Addr, example.com for a Domain-Name, https://example.com/page for a Url).',
  hashes: 'Hashes of the content, as a list of { algorithm, hash } entries (e.g. [{ algorithm: "SHA-256", hash: "..." }]), the algorithm being MD5, SHA-1, SHA-256, SHA-512, SHA3-256, SHA3-512, SSDEEP, SDHASH, TLSH or LZJD. In a STIX bundle, an object keyed by algorithm instead.',
  mime_type: 'MIME type of the content (e.g. application/pdf).',
  content_type: 'MIME content type, with its parameters (e.g. text/plain; charset=utf-8, multipart/mixed).',
  extensions: 'STIX extensions of the observable, as JSON.',
  ctime: 'Date when it was created on the file system, in ISO 8601.',
  mtime: 'Date when it was last modified on the file system, in ISO 8601.',
  atime: 'Date when it was last accessed on the file system, in ISO 8601.',
  // -- Refs --
  createdBy: 'Author of the entity: an identity (organization, individual, sector or system).',
  objectMarking: 'Marking definitions (e.g. TLP:AMBER) restricting who can see the entity.',
  objectLabel: 'Labels tagging the entity.',
  externalReferences: 'External references (source URL, report…) of the entity.',
  objectOrganization: 'Organizations the entity is shared with. The platform may ignore this field or set it itself.',
  objectAssignee: 'Users assigned to the entity.',
  objectParticipant: 'Users participating in the entity.',
  killChainPhases: 'Kill chain phases (e.g. MITRE ATT&CK tactics) the entity belongs to.',
  objects: 'Entities and relationships contained in the container.',
  // Observable refs
  containsObservable: 'Observables contained in this one: the files and directories of a directory, the files, artifacts, URLs and email addresses of an email, the observables embedded in a file.',
  resolvesTo: 'What the observable resolves to: IP addresses or domain names (CNAME) for a domain name, MAC addresses for an IP address.',
  belongsTo: 'What the address belongs to: the user account of an email address, the autonomous system of an IP address.',
  creatorUser: 'User account that created the process or the registry key.',
};

// Descriptions of the attributes used by a single type, and overrides where a shared name does
// not mean the same as elsewhere
export const ATTRIBUTE_DESCRIPTIONS_BY_TYPE: Record<string, Record<string, string>> = {
  // -- Domain objects --
  [ENTITY_TYPE_IDENTITY_ORGANIZATION]: {
    x_opencti_organization_type: 'Type of the organization, from the organization_type_ov vocabulary (e.g. vendor, partner, csirt).',
  },
  [ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM]: {
    security_platform_type: 'Type of the security platform, from the security_platform_type_ov vocabulary (e.g. EDR, SIEM).',
  },
  [ENTITY_TYPE_IDENTITY_SYSTEM]: {
    x_opencti_system_category: 'Asset category of the system, from the system_category_ov vocabulary (e.g. HOST, CLOUD_RESOURCE, WEB_APPLICATION).',
    x_opencti_system_subcategory: 'Asset subcategory of the system, from the system_subcategory_ov vocabulary (e.g. SERVER, LAPTOP, KUBERNETES_POD); each one belongs to a category.',
    x_opencti_internet_facing: 'Whether the system is reachable from the internet, from the system_internet_facing_ov vocabulary (yes, no or unknown).',
    x_opencti_criticality: 'Business criticality of the system, from the system_criticality_ov vocabulary (VERY_HIGH, HIGH, MEDIUM, LOW or UNKNOWN).',
    x_opencti_environment: 'Environment of the system, from the system_environment_ov vocabulary (e.g. production, staging, development).',
    x_opencti_owner: 'Owner of the system: the person or team responsible for the asset.',
    x_opencti_platform: 'Platform of the system, from the system_platform_ov vocabulary (e.g. Linux, Windows, Container).',
  },
  [ENTITY_TYPE_LOCATION_POSITION]: {
    street_address: 'Street address of the position.',
    postal_code: 'Postal code of the position.',
  },
  [ENTITY_TYPE_THREAT_ACTOR_GROUP]: {
    roles: 'Roles of the threat actor group, from the threat_actor_group_role_ov vocabulary (e.g. agent, director, sponsor).',
  },
  [ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL]: {
    date_of_birth: 'Date of birth of the threat actor, in ISO 8601.',
    gender: 'Gender of the threat actor, from the gender_ov vocabulary.',
    marital_status: 'Marital status of the threat actor, from the marital_status_ov vocabulary.',
    job_title: 'Job title of the threat actor.',
    eye_color: 'Eye color of the threat actor, from the eye_color_ov vocabulary.',
    hair_color: 'Hair color of the threat actor, from the hair_color_ov vocabulary.',
    height: 'Heights of the threat actor over time: each has a measure in centimeters and a date_seen.',
    weight: 'Weights of the threat actor over time: each has a measure in kilograms and a date_seen.',
    bornIn: 'Country where the threat actor was born.',
    ethnicity: 'Country of the ethnicity of the threat actor.',
    roles: 'Roles of the threat actor, from the threat_actor_individual_role_ov vocabulary (e.g. agent, director, sponsor).',
  },
  [ENTITY_TYPE_MALWARE]: {
    malware_types: 'Types of the malware, from the malware_type_ov vocabulary (e.g. ransomware, backdoor, trojan).',
    is_family: 'Whether the malware is a family (true) or a single instance (false).',
    architecture_execution_envs: 'Processor architectures the malware runs on, from the processor_architecture_ov vocabulary (e.g. x86, arm).',
    implementation_languages: 'Programming languages the malware is written in, from the implementation_language_ov vocabulary.',
    capabilities: 'Capabilities of the malware, from the malware_capabilities_ov vocabulary (e.g. exfiltrates-data, persists-after-system-reboot).',
    samples: 'Files or artifacts that are samples of the malware.',
    operatingSystems: 'Operating systems the malware runs on, as Software observables.',
  },
  [ENTITY_TYPE_TOOL]: {
    tool_types: 'Types of the tool, from the tool_types_ov vocabulary (e.g. remote-access, credential-exploitation).',
    tool_version: 'Version of the tool.',
  },
  [ENTITY_TYPE_INFRASTRUCTURE]: {
    infrastructure_types: 'Types of the infrastructure, from the infrastructure_type_ov vocabulary (e.g. botnet, command-and-control).',
  },
  [ENTITY_TYPE_CHANNEL]: {
    channel_types: 'Types of the channel, from the channel_types_ov vocabulary (e.g. Twitter, Facebook).',
  },
  [ENTITY_TYPE_NARRATIVE]: {
    narrative_types: 'Types of the narrative.',
  },
  [ENTITY_TYPE_EVENT]: {
    event_types: 'Types of the event, from the event_type_ov vocabulary (e.g. conference, sport-competition).',
    start_time: 'Date when the event started, in ISO 8601.',
    stop_time: 'Date when the event ended, in ISO 8601.',
  },
  [ENTITY_TYPE_ATTACK_PATTERN]: {
    x_mitre_permissions_required: 'Permissions needed to use the technique, from the permissions_ov vocabulary (e.g. User, Administrator).',
    x_mitre_detection: 'How to detect the technique.',
  },
  [ENTITY_TYPE_DATA_SOURCE]: {
    collection_layers: 'Layers the data source collects from, from the collection_layers_ov vocabulary (e.g. host, network, cloud).',
  },
  [ENTITY_TYPE_DATA_COMPONENT]: {
    dataSource: 'Data source the data component belongs to.',
  },
  [ENTITY_TYPE_INDICATOR]: {
    pattern: 'Detection pattern of the indicator, written in the language given by pattern_type (e.g. [ipv4-addr:value = \'198.51.100.1\'] in STIX).',
    pattern_type: 'Language of the pattern, from the pattern_type_ov vocabulary (e.g. stix, yara, sigma, snort).',
    indicator_types: 'Types of the indicator, from the indicator_type_ov vocabulary (e.g. malicious-activity, anomalous-activity).',
    valid_from: 'Date from which the indicator is valid, in ISO 8601.',
    valid_until: 'Date until which the indicator is valid, in ISO 8601.',
    x_opencti_main_observable_type: 'Type of the main observable the pattern detects (e.g. IPv4-Addr, Domain-Name, StixFile).',
    decay_exclusion_applied_rule: 'Decay exclusion rule applied to the indicator. Set by the platform.',
  },
  [ENTITY_TYPE_INCIDENT]: {
    incident_type: 'Type of the incident, from the incident_type_ov vocabulary (e.g. data-leak, ransomware, phishing).',
    source: 'Source that reported the incident.',
  },
  [ENTITY_TYPE_VULNERABILITY]: {
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
    x_opencti_affected_products: 'Affected products, one entry per product and version range: vendor, product, CPE or PURL pattern, version scheme (semver, deb, rpm, generic), start and end versions with their inclusive flags, and the first fixed version.',
  },
  [ENTITY_TYPE_CONTAINER_REPORT]: {
    published: 'Date when the report was published, in ISO 8601.',
    report_types: 'Types of the report, from the report_types_ov vocabulary (e.g. threat-report, internal-report).',
  },
  [ENTITY_TYPE_CONTAINER_GROUPING]: {
    context: 'Context of the grouping, from the grouping_context_ov vocabulary (e.g. suspicious-activity, malware-analysis).',
  },
  [ENTITY_TYPE_CONTAINER_NOTE]: {
    attribute_abstract: 'Short summary of the note.',
    note_types: 'Types of the note, from the note_types_ov vocabulary (e.g. analysis, assessment).',
    likelihood: 'Likelihood that the note is true, from 0 to 100.',
    content: 'Text of the note, in Markdown.',
  },
  [ENTITY_TYPE_CONTAINER_OPINION]: {
    opinion: 'Agreement with the information, from the opinion_ov vocabulary (strongly-disagree to strongly-agree).',
    explanation: 'Explanation of the opinion.',
  },
  [ENTITY_TYPE_CONTAINER_OBSERVED_DATA]: {
    first_observed: 'Start of the observation window, in ISO 8601.',
    last_observed: 'End of the observation window, in ISO 8601.',
    number_observed: 'Number of times the data was observed in the window.',
    number_seen: 'Number of times the objects were seen.',
    max_distinct_count: 'Highest number of distinct values observed.',
  },
  [ENTITY_TYPE_CONTAINER_CASE_INCIDENT]: {
    response_types: 'Types of response to the incident, from the incident_response_types_ov vocabulary (e.g. ransomware, data-leak).',
  },
  [ENTITY_TYPE_CONTAINER_CASE_RFI]: {
    information_types: 'Types of information requested, from the request_for_information_types_ov vocabulary.',
    x_opencti_request_access: 'Request for access to restricted knowledge, as JSON. Set by the platform when a user requests access.',
  },
  [ENTITY_TYPE_CONTAINER_CASE_RFT]: {
    takedown_types: 'Types of takedown requested, from the request_for_takedown_types_ov vocabulary (e.g. phishing, brand-abuse).',
  },
  [ENTITY_TYPE_CONTAINER_FEEDBACK]: {
    rating: 'Rating given in the feedback, from 1 to 5.',
  },
  [ENTITY_TYPE_CONTAINER_TASK]: {
    due_date: 'Date when the task is due, in ISO 8601.',
  },
  [ENTITY_TYPE_MALWARE_ANALYSIS]: {
    product: 'Name of the product that ran the analysis (e.g. a sandbox).',
    configuration_version: 'Version of the configuration used for the analysis.',
    modules: 'Modules of the analysis product used for the analysis.',
    analysis_engine_version: 'Version of the analysis engine.',
    analysis_definition_version: 'Version of the definitions (signatures) used by the analysis engine.',
    submitted: 'Date when the sample was submitted for analysis, in ISO 8601.',
    analysis_started: 'Date when the analysis started, in ISO 8601.',
    analysis_ended: 'Date when the analysis ended, in ISO 8601.',
    result_name: 'Classification name given by the analysis (e.g. a malware family).',
    result: 'Verdict of the analysis, from the malware_result_ov vocabulary (malicious, suspicious, benign, unknown).',
    analysisSample: 'Sample (file, artifact, network traffic or domain) analyzed.',
    analysisSco: 'Observables found by the analysis.',
    operatingSystem: 'Operating system of the analysis environment, as a Software observable.',
    hostVm: 'Virtual machine hosting the analysis, as a Software observable.',
    installedSoftware: 'Software installed in the analysis environment.',
    // version is too common (software, certificate, connector…) to be shared
    version: 'Version of the analysis product.',
  },
  [ENTITY_TYPE_SECURITY_COVERAGE]: {
    periodicity: 'How often the coverage is assessed, or how long a manual coverage is valid, as an ISO 8601 duration (e.g. P1D).',
    duration: 'Duration of a coverage assessment, as an ISO 8601 duration (e.g. PT1H).',
    type_affinity: 'Type of asset the coverage targets (e.g. ENDPOINT).',
    platforms_affinity: 'Platforms the coverage targets, from the platforms_ov vocabulary (e.g. windows, linux).',
    auto_enrichment_disable: 'Whether the enrichment connectors are prevented from assessing the coverage (manual coverage).',
    objectCovered: 'Entity (intrusion set, campaign, incident or report) whose coverage is assessed.',
    resultOf: 'Results of the security coverage.',
  },
  // resultOf links the coverage to its results, and a result to its single parent coverage
  [ENTITY_TYPE_SECURITY_COVERAGE_RESULT]: {
    resultOf: 'Security coverage this result belongs to.',
  },
  // -- Sighting --
  [STIX_SIGHTING_RELATIONSHIP]: {
    attribute_count: 'Number of times the entity was sighted.',
    x_opencti_negative: 'Whether the sighting is a false positive.',
    first_seen: 'Date of the first sighting, in ISO 8601.',
    last_seen: 'Date of the last sighting, in ISO 8601.',
  },
  // -- Observables --
  [ENTITY_AUTONOMOUS_SYSTEM]: {
    number: 'Number of the autonomous system (e.g. 15169).',
    rir: 'Regional Internet Registry that assigned the number (e.g. RIPE NCC, ARIN).',
  },
  [ENTITY_DIRECTORY]: {
    path: 'Path of the directory (e.g. C:\\Windows\\System32).',
    path_enc: 'Encoding of the path, as a character set name (e.g. UTF-8).',
  },
  [ENTITY_HASHED_OBSERVABLE_STIX_FILE]: {
    size: 'Size of the file, in bytes.',
    name_enc: 'Encoding of the file name, as a character set name (e.g. UTF-8).',
    magic_number_hex: 'Magic number of the file, in hexadecimal (e.g. 25504446 for a PDF).',
    parentDirectory: 'Directory containing the file.',
    obsContent: 'Artifact holding the content of the file.',
  },
  [ENTITY_HASHED_OBSERVABLE_ARTIFACT]: {
    payload_bin: 'Content of the artifact, encoded in base64.',
    encryption_algorithm: 'Algorithm used to encrypt the payload: AES-256-GCM, ChaCha20-Poly1305 or mime-type-indicated.',
    decryption_key: 'Key to decrypt the payload.',
    url: 'URL from which the content of the artifact can be downloaded.',
  },
  [ENTITY_EMAIL_ADDR]: {
    display_name: 'Display name of the owner of the address (e.g. Jane Doe).',
  },
  [ENTITY_EMAIL_MESSAGE]: {
    is_multipart: 'Whether the email body is made of MIME parts.',
    attribute_date: 'Date when the email was sent, in ISO 8601.',
    message_id: 'Message-ID header of the email.',
    received_lines: 'Received header lines of the email, in order.',
    emailFrom: 'Email address of the author of the email (From header).',
    emailSender: 'Email address of the sender of the email (Sender header), when it differs from the author.',
    emailTo: 'Email addresses of the recipients (To header).',
    emailCc: 'Email addresses of the recipients in copy (Cc header).',
    emailBcc: 'Email addresses of the recipients in blind copy (Bcc header).',
    bodyMultipart: 'MIME parts of the body of a multipart email.',
    rawEmail: 'Artifact holding the raw email, headers included.',
    subject: 'Subject line of the email.',
    body: 'Body of the email, when it is not multipart.',
  },
  [ENTITY_EMAIL_MIME_PART_TYPE]: {
    content_disposition: 'Content-Disposition header of the MIME part (e.g. attachment; filename="invoice.pdf").',
    bodyRaw: 'Artifact or file holding the raw content of the MIME part.',
    body: 'Decoded content of the MIME part, when it is text; otherwise bodyRaw holds it.',
  },
  [ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE]: {
    is_self_signed: 'Whether the certificate is self-signed.',
    serial_number: 'Serial number of the certificate, in hexadecimal.',
    signature_algorithm: 'Algorithm used to sign the certificate (e.g. sha256WithRSAEncryption).',
    issuer: 'Distinguished name of the certificate issuer (e.g. C=US, O=Example CA, CN=Example Root).',
    validity_not_before: 'Date from which the certificate is valid, in ISO 8601.',
    validity_not_after: 'Date until which the certificate is valid, in ISO 8601.',
    subject_public_key_algorithm: 'Algorithm of the subject public key (e.g. rsaEncryption).',
    subject_public_key_modulus: 'Modulus of the subject RSA public key, in hexadecimal.',
    subject_public_key_exponent: 'Exponent of the subject RSA public key (e.g. 65537).',
    basic_constraints: 'Basic Constraints extension of the certificate (e.g. CA:TRUE, pathlen:0).',
    name_constraints: 'Name Constraints extension of the certificate.',
    policy_constraints: 'Policy Constraints extension of the certificate.',
    key_usage: 'Key Usage extension of the certificate (e.g. digitalSignature, keyEncipherment).',
    extended_key_usage: 'Extended Key Usage extension of the certificate (e.g. serverAuth, clientAuth).',
    subject_key_identifier: 'Subject Key Identifier extension of the certificate, in hexadecimal.',
    authority_key_identifier: 'Authority Key Identifier extension of the certificate.',
    subject_alternative_name: 'Subject Alternative Name extension of the certificate (e.g. DNS:example.com).',
    issuer_alternative_name: 'Issuer Alternative Name extension of the certificate.',
    subject_directory_attributes: 'Subject Directory Attributes extension of the certificate.',
    crl_distribution_points: 'CRL Distribution Points extension of the certificate: where its revocation list is published.',
    inhibit_any_policy: 'Inhibit anyPolicy extension of the certificate.',
    private_key_usage_period_not_before: 'Date from which the private key may be used, in ISO 8601.',
    private_key_usage_period_not_after: 'Date until which the private key may be used, in ISO 8601.',
    certificate_policies: 'Certificate Policies extension of the certificate.',
    policy_mappings: 'Policy Mappings extension of the certificate.',
    version: 'Version of the X.509 encoding of the certificate (e.g. 3).',
    subject: 'Distinguished name of the certificate subject (e.g. C=US, O=Example, CN=www.example.com).',
  },
  [ENTITY_NETWORK_TRAFFIC]: {
    start: 'Date when the network traffic started, in ISO 8601.',
    end: 'Date when the network traffic ended, in ISO 8601.',
    is_active: 'Whether the network traffic is still ongoing.',
    src_port: 'Source port, from 0 to 65535.',
    dst_port: 'Destination port, from 0 to 65535.',
    protocols: 'Protocols of the traffic, from the outermost to the innermost layer (e.g. ipv4, tcp, http).',
    src_byte_count: 'Number of bytes sent from the source to the destination.',
    dst_byte_count: 'Number of bytes sent from the destination to the source.',
    src_packets: 'Number of packets sent from the source to the destination.',
    dst_packets: 'Number of packets sent from the destination to the source.',
    networkSrc: 'Source address of the traffic (IPv4, IPv6, MAC address or domain name).',
    networkDst: 'Destination address of the traffic (IPv4, IPv6, MAC address or domain name).',
    srcPayload: 'Artifact holding the payload sent from the source.',
    dstPayload: 'Artifact holding the payload sent from the destination.',
    networkEncapsulates: 'Network traffics encapsulated in this one.',
    encapsulatedBy: 'Network traffic encapsulating this one.',
  },
  [ENTITY_PROCESS]: {
    is_hidden: 'Whether the process is hidden.',
    pid: 'Process identifier.',
    created_time: 'Date when the process was created, in ISO 8601.',
    cwd: 'Current working directory of the process.',
    command_line: 'Full command line of the process, with its arguments.',
    environment_variables: 'Environment variables of the process, as NAME=value strings (e.g. PATH=/usr/bin).',
    aslr_enabled: 'Whether Address Space Layout Randomization is enabled for the process.',
    dep_enabled: 'Whether Data Execution Prevention is enabled for the process.',
    owner_sid: 'Security identifier (SID) of the owner of the Windows process.',
    window_title: 'Title of the main window of the Windows process.',
    integrity_level: 'Windows integrity level of the process, from the integrity_level_ov vocabulary.',
    service_name: 'Name of the Windows service.',
    descriptions: 'Descriptions of the Windows service.',
    group_name: 'Name of the load ordering group of the Windows service.',
    start_type: 'Start type of the Windows service, from the start_type_ov vocabulary (e.g. SERVICE_AUTO_START, SERVICE_DEMAND_START).',
    service_type: 'Type of the Windows service, from the service_type_ov vocabulary (e.g. SERVICE_WIN32_OWN_PROCESS, SERVICE_KERNEL_DRIVER).',
    service_status: 'Status of the Windows service, from the service_status_ov vocabulary (e.g. SERVICE_RUNNING, SERVICE_STOPPED).',
    openedConnections: 'Network traffics opened by the process.',
    processImage: 'Executable file of the process.',
    processParent: 'Parent process.',
    processChild: 'Child processes.',
    serviceDlls: 'DLL files loaded by the Windows service.',
    priority: 'Priority of the Windows process, from the case_priority_ov vocabulary.',
    display_name: 'Display name of the Windows service.',
  },
  [ENTITY_SOFTWARE]: {
    cpe: 'CPE 2.3 identifier of the software (e.g. cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*).',
    swid: 'SWID tag identifier of the software.',
    languages: 'Languages supported by the software, as ISO 639-2 codes (e.g. eng, fra).',
    vendor: 'Vendor of the software (e.g. Microsoft).',
    version: 'Version of the software (e.g. 2.4.58).',
  },
  [ENTITY_USER_ACCOUNT]: {
    user_id: 'Identifier of the account in its system (e.g. a UID such as 1001, or a Windows SID).',
    credential: 'Clear-text credential of the account (e.g. a password).',
    account_login: 'Login of the account (e.g. jdoe).',
    account_type: 'Type of the account, from the account_type_ov vocabulary (e.g. unix, windows-domain, ldap).',
    is_service_account: 'Whether the account is used by a service rather than a person.',
    is_privileged: 'Whether the account has elevated privileges (e.g. root, administrator).',
    can_escalate_privs: 'Whether the account can escalate its privileges (e.g. through sudo).',
    is_disabled: 'Whether the account is disabled.',
    account_created: 'Date when the account was created, in ISO 8601.',
    account_expires: 'Date when the account expires, in ISO 8601.',
    credential_last_changed: 'Date when the credential was last changed, in ISO 8601.',
    account_first_login: 'Date of the first login on the account, in ISO 8601.',
    account_last_login: 'Date of the last login on the account, in ISO 8601.',
    display_name: 'Display name of the owner of the account (e.g. Jane Doe).',
  },
  [ENTITY_WINDOWS_REGISTRY_KEY]: {
    attribute_key: 'Full path of the registry key (e.g. HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run).',
    modified_time: 'Date when the registry key was last modified, in ISO 8601.',
    number_of_subkeys: 'Number of subkeys of the registry key.',
    winRegValues: 'Values of the registry key.',
  },
  [ENTITY_WINDOWS_REGISTRY_VALUE_TYPE]: {
    data: 'Data of the registry value.',
    data_type: 'Type of the registry value data (e.g. REG_SZ, REG_DWORD).',
  },
  [ENTITY_BANK_ACCOUNT]: {
    iban: 'International Bank Account Number of the account.',
    bic: 'Bank Identifier Code (SWIFT) of the bank.',
    account_number: 'Number of the bank account.',
  },
  [ENTITY_PAYMENT_CARD]: {
    card_number: 'Number of the payment card.',
    cvv: 'Card verification value of the payment card.',
    holder_name: 'Name of the payment card holder.',
    expiration_date: 'Expiration date of the payment card, in ISO 8601.',
  },
  [ENTITY_MEDIA_CONTENT]: {
    title: 'Title of the media.',
    media_category: 'Category of the media (e.g. article, video, social media post).',
    publication_date: 'Date when the media was published, in ISO 8601.',
    content: 'Text content of the media (e.g. the body of an article or a post).',
    url: 'URL of the media.',
  },
  [ENTITY_PERSONA]: {
    persona_name: 'Name of the persona (e.g. an online handle).',
    persona_type: 'Type of the persona (e.g. a social media platform or a forum).',
  },
  [ENTITY_SSH_KEY]: {
    key_type: 'Algorithm of the SSH key, from the key_type_ov vocabulary (e.g. rsa, ed25519).',
    public_key: 'SSH public key, in OpenSSH format.',
    fingerprint_sha256: 'SHA-256 fingerprint of the SSH key.',
    fingerprint_md5: 'MD5 fingerprint of the SSH key.',
    key_length: 'Length of the SSH key, in bits (e.g. 4096).',
    comment: 'Comment attached to the SSH key (e.g. user@host).',
    created: 'Date when the SSH key was generated, in ISO 8601.',
    expiration_date: 'Date when the SSH key expires, in ISO 8601.',
  },
  // -- Meta objects --
  [ENTITY_TYPE_MARKING_DEFINITION]: {
    definition_type: 'Type of the marking, grouping the markings compared by their order (e.g. TLP, PAP).',
    definition: 'Name of the marking: the built-in TLP and PAP markings use the TYPE:LEVEL form (e.g. TLP:GREEN, PAP:AMBER), a custom marking any text (e.g. a statement or a copyright notice).',
    x_opencti_order: 'Level of the marking within its type: the higher, the more restrictive (e.g. 1 for TLP:CLEAR, 5 for TLP:RED).',
    x_opencti_color: 'Display color of the marking, as a hexadecimal code (e.g. #2e7d32).',
  },
  [ENTITY_TYPE_LABEL]: {
    value: 'Text of the label, matched whatever its letter case (e.g. phishing).',
    color: 'Display color of the label, as a hexadecimal code (e.g. #2e7d32). Generated from the value when not given.',
  },
  [ENTITY_TYPE_EXTERNAL_REFERENCE]: {
    source_name: 'Name of the source the reference comes from (e.g. mitre-attack, cve, a vendor name).',
    description: 'Description of the reference.',
    url: 'URL of the referenced content.',
    hash: 'Hash of the content found at the URL, as free text (e.g. a SHA-256). Stored as is, not used by the platform.',
    external_id: 'Identifier of the referenced content in its source (e.g. T1566 in mitre-attack, CVE-2021-44228 in cve).',
    fileId: 'Id of the file uploaded with the reference in the platform storage, its URL then pointing to the file. Set by the platform.',
  },
  [ENTITY_TYPE_KILL_CHAIN_PHASE]: {
    kill_chain_name: 'Name of the kill chain (e.g. mitre-attack, lockheed-martin-cyber-kill-chain).',
    phase_name: 'Name of the phase in the kill chain (e.g. initial-access, exfiltration).',
    x_opencti_order: 'Position of the phase in its kill chain, to sort the phases. Defaults to 0.',
  },
  [ENTITY_TYPE_VOCABULARY]: {
    color: 'Display color in the platform, as a hexadecimal code (e.g. #2e7d32).',
    name: 'Value of the entry, as set in the fields using its vocabulary (e.g. ransomware in malware_type_ov).',
    description: 'Meaning of the entry.',
    category: 'Vocabulary the entry belongs to (e.g. malware_type_ov, report_types_ov).',
    order: 'Position of the entry in its vocabulary, to sort the entries. Defaults to 0.',
    parent_name: 'Name of the parent entry in the same vocabulary (e.g. the system category of a system subcategory). Kept when the parent entry is renamed.',
    is_hidden: 'Whether the entry is hidden from the choices offered when filling a field.',
    builtIn: 'Whether the entry is provided by the platform: a built-in entry cannot be deleted. Set by the platform.',
  },
};

// The types whose attributes and refs the dictionary was written for: the STIX domain objects,
// observables, relationships and sightings, and the meta objects (markings, labels, external
// references, kill chain phases and the OpenCTI vocabulary entries). Elsewhere a same name can mean
// something else (the content of a workflow definition is JSON, its author is a user…): a wrong
// description being worse than none, the internal types get no description.
export const isDescribedType = (entityType: string): boolean => isStixDomainObject(entityType) || isStixCyberObservable(entityType)
  || isStixCoreRelationship(entityType) || isStixSightingRelationship(entityType) || isStixMetaObject(entityType);

// Resolution order: the description written in the definition, then the override of the type,
// then the dictionary for a described type only
export const resolveAttributeDescription = (entityType: string, attribute: { name: string; description?: string }): string | null => {
  return attribute.description
    ?? ATTRIBUTE_DESCRIPTIONS_BY_TYPE[entityType]?.[attribute.name]
    ?? (isDescribedType(entityType) ? ATTRIBUTE_DESCRIPTIONS[attribute.name] : undefined)
    ?? null;
};
