import { z } from 'zod';
import { FilterMode, FilterOperator } from '../../generated/graphql';

// =======================
// Modes
// =======================

export const modeDescription = {
  [FilterMode.And]: {
    description: 'Requires all filter conditions to be met (logical AND).',
  },
  [FilterMode.Or]: {
    description:
      'Requires at least one filter condition to be met (logical OR).',
  },
};

export const modeKeys = Object.values(FilterMode);

// =======================
// Operators
// =======================

export const operatorDescription = {
  [FilterOperator.Contains]: {
    description: 'Filters for values that contain the given substring.',
  },
  [FilterOperator.EndsWith]: {
    description: 'Filters for values that end with the given substring.',
  },
  [FilterOperator.Eq]: {
    description: 'Filters for values that exactly match the given criterion.',
  },
  [FilterOperator.Gt]: {
    description: 'Filters for values greater than the given numeric value.',
  },
  [FilterOperator.Gte]: {
    description:
      'Filters for values greater than or equal to the given numeric value.',
  },
  [FilterOperator.Lt]: {
    description: 'Filters for values less than the given numeric value.',
  },
  [FilterOperator.Lte]: {
    description:
      'Filters for values less than or equal to the given numeric value.',
  },
  [FilterOperator.Match]: {
    description:
      'Filters for values that match a specified pattern (regex or similar).',
  },
  [FilterOperator.Nil]: {
    description: 'Filters for values that are null or missing.',
  },
  [FilterOperator.NotContains]: {
    description:
      "Inverse of 'contains'; filters for values not containing the substring.",
  },
  [FilterOperator.NotEndsWith]: {
    description:
      "Inverse of 'ends_with'; filters for values not ending with the substring.",
  },
  [FilterOperator.NotEq]: {
    description:
      "Inverse of 'eq'; filters for values that do not match the given criterion.",
  },
  [FilterOperator.NotNil]: {
    description: 'Filters for values that are not null or missing.',
  },
  [FilterOperator.NotStartsWith]: {
    description:
      "Inverse of 'starts_with'; filters for values not starting with the substring.",
  },
  [FilterOperator.Script]: {
    description: 'Filters using a custom script or expression.',
  },
  [FilterOperator.Search]: {
    description: 'Full-text or specialized search operator.',
  },
  [FilterOperator.StartsWith]: {
    description: 'Filters for values that start with the given substring.',
  },
  [FilterOperator.Wildcard]: {
    description:
      'Filters for values matching a wildcard pattern (e.g., * or ?).',
  },
  [FilterOperator.Within]: {
    description:
      'Filters for values falling within the specified boundaries or range (e.g., between two numbers or dates).',
  },
};

export const operatorKeys = Object.values(FilterOperator);

// =======================
// Relationship
// =======================

enum RelationshipEnum {
  AMPLIFIES = 'amplifies',
  ANALYSIS_OF = 'analysis-of',
  ATTRIBUTED_TO = 'attributed-to',
  AUTHORED_BY = 'authored-by',
  BASED_ON = 'based-on',
  BEACONS_TO = 'beacons-to',
  BELONGS_TO = 'belongs-to',
  CHARACTERIZES = 'characterizes',
  CITIZEN_OF = 'citizen-of',
  COMMUNICATES_WITH = 'communicates-with',
  COMPROMISES = 'compromises',
  CONSISTS_OF = 'consists-of',
  CONTROLS = 'controls',
  COOPERATES_WITH = 'cooperates-with',
  DELIVERS = 'delivers',
  DERIVED_FROM = 'derived-from',
  DETECTS = 'detects',
  DOWNLOADS = 'downloads',
  DROPS = 'drops',
  DUPLICATE_OF = 'duplicate-of',
  DYNAMIC_ANALYSIS_OF = 'dynamic-analysis-of',
  EMPLOYED_BY = 'employed-by',
  EXFILTRATES_TO = 'exfiltrates-to',
  EXPLOITS = 'exploits',
  HAS = 'has',
  HOSTS = 'hosts',
  IMPERSONATES = 'impersonates',
  INDICATES = 'indicates',
  INVESTIGATES = 'investigates',
  KNOWN_AS = 'known-as',
  LOCATED_AT = 'located-at',
  MITIGATES = 'mitigates',
  NATIONAL_OF = 'national-of',
  ORIGINATES_FROM = 'originates-from',
  OWNS = 'owns',
  PART_OF = 'part-of',
  PARTICIPATES_IN = 'participates-in',
  PUBLISHES = 'publishes',
  RELATED_TO = 'related-to',
  REMEDIATES = 'remediates',
  REPORTS_TO = 'reports-to',
  RESIDES_IN = 'resides-in',
  RESOLVES_TO = 'resolves-to',
  REVOKED_BY = 'revoked-by',
  STATIC_ANALYSIS_OF = 'static-analysis-of',
  SUBNARRATIVE_OF = 'subnarrative-of',
  SUBTECHNIQUE_OF = 'subtechnique-of',
  SUPPORTS = 'supports',
  TARGETS = 'targets',
  USES = 'uses',
  VARIANT_OF = 'variant-of',
}

export const relationshipDescription = {
  [RelationshipEnum.ATTRIBUTED_TO]: {
    description: 'Indicates attribution to a threat actor or campaign.',
  },
  [RelationshipEnum.EXPLOITS]: {
    description: 'Indicates exploitation of a vulnerability or target.',
  },
  [RelationshipEnum.HAS]: {
    description: 'Expresses possession or inclusion.',
  },
  [RelationshipEnum.INDICATES]: {
    description: 'Suggests an indicator about an entity or relationship.',
  },
  [RelationshipEnum.LOCATED_AT]: {
    description: 'Specifies a geographic or physical location.',
  },
  [RelationshipEnum.ORIGINATES_FROM]: {
    description: 'Specifies origin or source location.',
  },
  [RelationshipEnum.PART_OF]: {
    description: 'Indicates a subcomponent of a bigger entity.',
  },
  [RelationshipEnum.RELATED_TO]: {
    description: 'Indicates a non-specific relationship between entities.',
  },
  [RelationshipEnum.SUBTECHNIQUE_OF]: {
    description: 'Specifies that this is a subtechnique of a broader tactic.',
  },
  [RelationshipEnum.TARGETS]: {
    description:
      'Indicates targeting of an individual, organization, or system.',
  },
  [RelationshipEnum.USES]: {
    description: 'Indicates usage of a tool, malware, or technique.',
  },
  [RelationshipEnum.AMPLIFIES]: {
    description: 'Increases the impact or effect of another entity.',
  },
  [RelationshipEnum.ANALYSIS_OF]: {
    description: 'Denotes an analysis performed on another entity.',
  },
  [RelationshipEnum.AUTHORED_BY]: {
    description: 'Identifies the author of an entity or document.',
  },
  [RelationshipEnum.BASED_ON]: {
    description: 'Indicates a foundation or dependency on another entity.',
  },
  [RelationshipEnum.BEACONS_TO]: {
    description:
      'Indicates communication or signaling to a remote destination.',
  },
  [RelationshipEnum.BELONGS_TO]: {
    description: 'Indicates membership or ownership by another entity.',
  },
  [RelationshipEnum.CHARACTERIZES]: {
    description: 'Describes distinctive traits or qualities of another entity.',
  },
  [RelationshipEnum.CITIZEN_OF]: {
    description: 'Denotes citizenship or national belonging.',
  },
  [RelationshipEnum.COMMUNICATES_WITH]: {
    description: 'Indicates two entities communicate or exchange data.',
  },
  [RelationshipEnum.COMPROMISES]: {
    description: 'Indicates compromise or unauthorized access.',
  },
  [RelationshipEnum.CONSISTS_OF]: {
    description: 'Expresses that an entity is composed of other entities.',
  },
  [RelationshipEnum.CONTROLS]: {
    description: 'Denotes control or governance of another entity.',
  },
  [RelationshipEnum.COOPERATES_WITH]: {
    description: 'Indicates collaborative or cooperative behavior.',
  },
  [RelationshipEnum.DELIVERS]: {
    description: 'Indicates delivery of malware, payload, or content.',
  },
  [RelationshipEnum.DERIVED_FROM]: {
    description: 'Indicates origin from or derivation of another entity.',
  },
  [RelationshipEnum.DETECTS]: {
    description: 'Specifies detection or identification of another entity.',
  },
  [RelationshipEnum.DOWNLOADS]: {
    description: 'Indicates downloading actions.',
  },
  [RelationshipEnum.DROPS]: {
    description: 'Indicates deployment or dropping of malware.',
  },
  [RelationshipEnum.DUPLICATE_OF]: {
    description: 'Indicates duplication or identical copy.',
  },
  [RelationshipEnum.DYNAMIC_ANALYSIS_OF]: {
    description: 'Denotes dynamic analysis conducted on another entity.',
  },
  [RelationshipEnum.EMPLOYED_BY]: {
    description: 'Indicates employment or working relationship.',
  },
  [RelationshipEnum.EXFILTRATES_TO]: {
    description: 'Specifies exfiltration of data to a destination.',
  },
  [RelationshipEnum.HOSTS]: {
    description: 'Indicates hosting of content, infrastructure, or malware.',
  },
  [RelationshipEnum.IMPERSONATES]: {
    description: 'Indicates impersonation or masquerading.',
  },
  [RelationshipEnum.INVESTIGATES]: {
    description: 'Denotes investigative action or inquiry.',
  },
  [RelationshipEnum.KNOWN_AS]: {
    description: 'Denotes alternate naming or alias.',
  },
  [RelationshipEnum.MITIGATES]: {
    description: 'Indicates mitigation actions.',
  },
  [RelationshipEnum.NATIONAL_OF]: {
    description: 'Denotes nationality or affiliation with a nation-state.',
  },
  [RelationshipEnum.OWNS]: {
    description: 'Expresses ownership or possession.',
  },
  [RelationshipEnum.VARIANT_OF]: {
    description: 'Specifies variant or related version.',
  },
  [RelationshipEnum.PARTICIPATES_IN]: {
    description: 'Indicates involvement in an operation, event, or activity.',
  },
  [RelationshipEnum.PUBLISHES]: {
    description:
      'Specifies that an entity publishes content, data, or reports.',
  },
  [RelationshipEnum.REMEDIATES]: {
    description:
      'Indicates that an entity addresses or fixes a vulnerability or issue.',
  },
  [RelationshipEnum.REPORTS_TO]: {
    description:
      'Specifies a hierarchical reporting relationship between entities.',
  },
  [RelationshipEnum.RESIDES_IN]: {
    description:
      'Specifies that an entity is located within a particular environment or jurisdiction.',
  },
  [RelationshipEnum.RESOLVES_TO]: {
    description:
      'Indicates that an entity, such as a domain name, resolves to another entity like an IP address.',
  },
  [RelationshipEnum.REVOKED_BY]: {
    description:
      'Specifies that an entity has been revoked or invalidated by another authority.',
  },
  [RelationshipEnum.STATIC_ANALYSIS_OF]: {
    description:
      'Indicates that an entity is derived from the static analysis of a sample or artifact.',
  },
  [RelationshipEnum.SUBNARRATIVE_OF]: {
    description:
      'Indicates that one narrative is a sub-part or subset of a larger narrative.',
  },
  [RelationshipEnum.SUPPORTS]: {
    description:
      'Specifies that an entity provides support, such as resources or expertise, to another entity.',
  },
};

export const relationshipKeysLarge = Object.values(RelationshipEnum);

export const relationshipKeysSmall = [
  RelationshipEnum.ATTRIBUTED_TO,
  RelationshipEnum.EXPLOITS,
  RelationshipEnum.HAS,
  RelationshipEnum.INDICATES,
  RelationshipEnum.LOCATED_AT,
  RelationshipEnum.ORIGINATES_FROM,
  RelationshipEnum.PART_OF,
  RelationshipEnum.RELATED_TO,
  RelationshipEnum.SUBTECHNIQUE_OF,
  RelationshipEnum.TARGETS,
  RelationshipEnum.USES,
];

// =======================
// Entities & Observables
// =======================

enum EntityObservableEnum {
  // Entity type
  ADMINISTRATIVE_AREA = 'Administrative-Area',
  ATTACK_PATTERN = 'Attack-Pattern',
  CAMPAIGN = 'Campaign',
  CHANNEL = 'Channel',
  CITY = 'City',
  COUNTRY = 'Country',
  COURSE_OF_ACTION = 'Course-Of-Action',
  DATA_COMPONENT = 'Data-Component',
  DATA_SOURCE = 'Data-Source',
  EVENT = 'Event',
  FEEDBACK = 'Feedback',
  GROUPING = 'Grouping',
  INCIDENT = 'Incident',
  CASE_INCIDENT = 'Case-Incident',
  INDICATOR = 'Indicator',
  INDIVIDUAL = 'Individual',
  INFRASTRUCTURE = 'Infrastructure',
  INTRUSION_SET = 'Intrusion-Set',
  LANGUAGE = 'Language',
  MALWARE = 'Malware',
  MALWARE_ANALYSIS = 'Malware-Analysis',
  NARRATIVE = 'Narrative',
  NOTE = 'Note',
  OBSERVED_DATA = 'Observed-Data',
  OPINION = 'Opinion',
  ORGANIZATION = 'Organization',
  POSITION = 'Position',
  REGION = 'Region',
  REPORT = 'Report',
  STIX_CYBER_OBSERVABLE = 'Stix-Cyber-Observable',
  CASE_RFI = 'Case-Rfi',
  CASE_RFT = 'Case-Rft',
  SECTOR = 'Sector',
  SYSTEM = 'System',
  TASK = 'Task',
  THREAT_ACTOR_GROUP = 'Threat-Actor-Group',
  THREAT_ACTOR_INDIVIDUAL = 'Threat-Actor-Individual',
  TOOL = 'Tool',
  VULNERABILITY = 'Vulnerability',
  // Observable type
  ARTIFACT = 'Artifact',
  AUTONOMOUS_SYSTEM = 'Autonomous-System',
  BANK_ACCOUNT = 'Bank-Account',
  CREDENTIAL = 'Credential',
  CRYPTOCURRENCY_WALLET = 'Cryptocurrency-Wallet',
  CRYPTOGRAPHIC_KEY = 'Cryptographic-Key',
  DIRECTORY = 'Directory',
  DOMAIN_NAME = 'Domain-Name',
  EMAIL_ADDR = 'Email-Addr',
  EMAIL_MESSAGE = 'Email-Message',
  EMAIL_MIME_PART_TYPE = 'Email-Mime-Part-Type',
  STIX_FILE = 'StixFile',
  HOSTNAME = 'Hostname',
  IPV4_ADDR = 'IPv4-Addr',
  IPV6_ADDR = 'IPv6-Addr',
  MAC_ADDR = 'Mac-Addr',
  MEDIA_CONTENT = 'Media-Content',
  MUTEX = 'Mutex',
  NETWORK_TRAFFIC = 'Network-Traffic',
  PAYMENT_CARD = 'Payment-Card',
  PERSONA = 'Persona',
  PHONE_NUMBER = 'Phone-Number',
  PROCESS = 'Process',
  SOFTWARE = 'Software',
  TEXT = 'Text',
  TRACKING_NUMBER = 'Tracking-Number',
  URL = 'Url',
  USER_ACCOUNT = 'User-Account',
  USER_AGENT = 'User-Agent',
  WINDOWS_REGISTRY_KEY = 'Windows-Registry-Key',
  WINDOWS_REGISTRY_VALUE_TYPE = 'Windows-Registry-Value-Type',
  X509_CERTIFICATE = 'X509-Certificate',
  SSH_KEY = 'SSH-Key',
  IMEI = 'IMEI',
  ICCID = 'ICCID',
  IMSI = 'IMSI'
}

export const entityObservableDescription = {
  // Entity
  [EntityObservableEnum.ADMINISTRATIVE_AREA]: {
    description:
      'Geographical or administrative boundary (non-standard STIX, OpenCTI extension).',
  },
  [EntityObservableEnum.ATTACK_PATTERN]: {
    description: 'STIX: TTP describing a malicious technique (MITRE ATT&CK).',
  },
  [EntityObservableEnum.CAMPAIGN]: {
    description:
      'STIX: A grouping of adversarial activity over a particular timeframe.',
  },
  [EntityObservableEnum.CHANNEL]: {
    description:
      'OpenCTI extension: A communication channel (IRC, Telegram, social media, etc.).',
  },
  [EntityObservableEnum.CITY]: {
    description: 'Geographical city-level object (OpenCTI extension).',
  },
  [EntityObservableEnum.COUNTRY]: {
    description: 'Geographical country-level object (OpenCTI extension).',
  },
  [EntityObservableEnum.COURSE_OF_ACTION]: {
    description:
      'STIX: A recommendation or guidance to prevent or respond to a threat.',
  },
  [EntityObservableEnum.DATA_COMPONENT]: {
    description:
      'Represents a subpart of a data source (common in detection definitions).',
  },
  [EntityObservableEnum.DATA_SOURCE]: {
    description:
      'STIX: A source of information used to collect relevant security data.',
  },
  [EntityObservableEnum.EVENT]: {
    description:
      'Generic event (OpenCTI). Could be a significant cybersecurity occurrence.',
  },
  [EntityObservableEnum.FEEDBACK]: {
    description:
      'User feedback or comment about an entity (OpenCTI extension).',
  },
  [EntityObservableEnum.GROUPING]: {
    description:
      'STIX: A set of objects grouped together for a specific context.',
  },
  [EntityObservableEnum.INCIDENT]: {
    description:
      'OpenCTI extension: A cybersecurity incident referencing a security breach.',
  },
  [EntityObservableEnum.CASE_INCIDENT]: {
    description:
      'OpenCTI extension: An incident case used for investigation workflows.',
  },
  [EntityObservableEnum.INDICATOR]: {
    description:
      'STIX: A pattern-based detection for suspicious or malicious activity (IOC).',
  },
  [EntityObservableEnum.INDIVIDUAL]: {
    description:
      'OpenCTI extension: An individual person relevant to an investigation.',
  },
  [EntityObservableEnum.INFRASTRUCTURE]: {
    description:
      'STIX: Adversarial or victim infrastructure (servers, domains, etc.).',
  },
  [EntityObservableEnum.INTRUSION_SET]: {
    description:
      'STIX: A grouped set of adversarial behaviors, resources, and patterns over time (APT group).',
  },
  [EntityObservableEnum.LANGUAGE]: {
    description:
      'OpenCTI extension: A spoken or programming language relevant to the entity.',
  },
  [EntityObservableEnum.MALWARE]: {
    description:
      'STIX: Malicious software such as ransomware, trojan, worm, etc.',
  },
  [EntityObservableEnum.MALWARE_ANALYSIS]: {
    description: 'STIX: The process or results of analyzing a malware sample.',
  },
  [EntityObservableEnum.NARRATIVE]: {
    description:
      'OpenCTI extension: A narrative or storyline used in reporting.',
  },
  [EntityObservableEnum.NOTE]: {
    description: 'STIX: A non-rewritable note containing user commentary.',
  },
  [EntityObservableEnum.OBSERVED_DATA]: {
    description:
      'STIX: Conveys raw information observed on systems or networks (logs, sensor data).',
  },
  [EntityObservableEnum.OPINION]: {
    description: 'STIX: A subjective assessment of the information provided.',
  },
  [EntityObservableEnum.ORGANIZATION]: {
    description:
      'An organization, company, or institution relevant to the CTI context.',
  },
  [EntityObservableEnum.POSITION]: {
    description:
      'A specific job position or role in an organization (OpenCTI extension).',
  },
  [EntityObservableEnum.REGION]: {
    description:
      'A broader geographic region (continent, supra-national zone).',
  },
  [EntityObservableEnum.REPORT]: {
    description:
      'STIX: A collection of threat intelligence detailing a set of related objects.',
  },
  [EntityObservableEnum.STIX_CYBER_OBSERVABLE]: {
    description:
      'STIX: A technical artifact or observable (file, domain, IP address, etc.).',
  },
  [EntityObservableEnum.CASE_RFI]: {
    description:
      'OpenCTI extension: A request for information in an investigation workflow.',
  },
  [EntityObservableEnum.CASE_RFT]: {
    description:
      'OpenCTI extension: A request for takedown in an investigation workflow.',
  },
  [EntityObservableEnum.SECTOR]: {
    description: 'An industry or business sector (finance, telecom, etc.).',
  },
  [EntityObservableEnum.SYSTEM]: {
    description:
      'A system or device relevant to an investigation or infrastructure.',
  },
  [EntityObservableEnum.TASK]: {
    description:
      'An action item in an operational or investigative workflow (OpenCTI extension).',
  },
  [EntityObservableEnum.THREAT_ACTOR_GROUP]: {
    description:
      'STIX: A collective threat actor entity (APT group, cybercriminal gang).',
  },
  [EntityObservableEnum.THREAT_ACTOR_INDIVIDUAL]: {
    description: 'STIX: A single individual threat actor.',
  },
  [EntityObservableEnum.TOOL]: {
    description:
      'STIX: A software tool used by threat actors, possibly dual-use (legitimate or malicious).',
  },
  [EntityObservableEnum.VULNERABILITY]: {
    description:
      'STIX: A flaw in software or hardware that can be exploited (e.g., CVE).',
  },
  // Observable
  [EntityObservableEnum.ARTIFACT]: {
    description: 'A physical or digital object used as evidence or reference.',
  },
  [EntityObservableEnum.AUTONOMOUS_SYSTEM]: {
    description:
      'A collection of IP networks and routers under common administration.',
  },
  [EntityObservableEnum.BANK_ACCOUNT]: {
    type: z.literal(EntityObservableEnum.BANK_ACCOUNT),
    description: 'A financial account held at a bank or financial institution.',
  },
  [EntityObservableEnum.CREDENTIAL]: {
    description:
      'Authentication information such as usernames, passwords, or tokens.',
  },
  [EntityObservableEnum.CRYPTOCURRENCY_WALLET]: {
    description: 'A digital wallet used to store cryptocurrency credentials.',
  },
  [EntityObservableEnum.CRYPTOGRAPHIC_KEY]: {
    description:
      'A key used in cryptographic operations, such as encryption or digital signatures.',
  },
  [EntityObservableEnum.DIRECTORY]: {
    description: 'A file system directory containing files and subdirectories.',
  },
  [EntityObservableEnum.DOMAIN_NAME]: {
    description: 'A human-readable address corresponding to an IP address.',
  },
  [EntityObservableEnum.EMAIL_ADDR]: {
    description: 'An email address used for communication.',
  },
  [EntityObservableEnum.EMAIL_MESSAGE]: {
    description: 'An email message object containing metadata and content.',
  },
  [EntityObservableEnum.EMAIL_MIME_PART_TYPE]: {
    description: 'The MIME type of a part within an email message.',
  },
  [EntityObservableEnum.STIX_FILE]: {
    description: 'A file object formatted in STIX.',
  },
  [EntityObservableEnum.HOSTNAME]: {
    description: 'A host name identifying a device on a network.',
  },
  [EntityObservableEnum.IPV4_ADDR]: {
    description: 'An IPv4 address.',
  },
  [EntityObservableEnum.IPV6_ADDR]: {
    description: 'An IPv6 address.',
  },
  [EntityObservableEnum.MAC_ADDR]: {
    description: 'A MAC address used for network interface identification.',
  },
  [EntityObservableEnum.MEDIA_CONTENT]: {
    description:
      'Digital media content such as images, videos, or audio files.',
  },
  [EntityObservableEnum.MUTEX]: {
    description:
      'A mutual exclusion object used to manage access to shared resources.',
  },
  [EntityObservableEnum.NETWORK_TRAFFIC]: {
    description: 'Data packets or flows representing network traffic.',
  },
  [EntityObservableEnum.PAYMENT_CARD]: {
    description:
      'Credit or debit card information used for financial transactions.',
  },
  [EntityObservableEnum.PERSONA]: {
    description: "A digital representation of an individual's online identity.",
  },
  [EntityObservableEnum.PHONE_NUMBER]: {
    description: 'A telephone number used for contact or communication.',
  },
  [EntityObservableEnum.PROCESS]: {
    description:
      'An instance of a running program or process in an operating system.',
  },
  [EntityObservableEnum.SOFTWARE]: {
    description: 'A software application or system.',
  },
  [EntityObservableEnum.TEXT]: {
    description: 'Plain textual content.',
  },
  [EntityObservableEnum.TRACKING_NUMBER]: {
    description: 'A number used to track shipments or other items.',
  },
  [EntityObservableEnum.URL]: {
    description:
      'A Uniform Resource Locator specifying the address of a resource on the internet.',
  },
  [EntityObservableEnum.USER_ACCOUNT]: {
    description:
      'An account representing a user, used for authentication and access control.',
  },
  [EntityObservableEnum.USER_AGENT]: {
    description:
      'A string representing the client software making a request (e.g., browser, bot).',
  },
  [EntityObservableEnum.WINDOWS_REGISTRY_KEY]: {
    description:
      'A key in the Windows Registry containing configuration settings.',
  },
  [EntityObservableEnum.WINDOWS_REGISTRY_VALUE_TYPE]: {
    description:
      'The type of a value in the Windows Registry (e.g., REG_SZ, REG_DWORD).',
  },
  [EntityObservableEnum.X509_CERTIFICATE]: {
    description: 'A digital certificate conforming to the X.509 standard.',
  },
  [EntityObservableEnum.SSH_KEY]: {
    description: 'A key used to securely authenticate to servers and services over SSH.',
  },
  [EntityObservableEnum.IMEI]: {
    description: 'An identifier used to identify a specific mobile device.',
  },
  [EntityObservableEnum.ICCID]: {
    description: 'An identifier used to identify a specific SIM card.',
  },
  [EntityObservableEnum.IMSI]: {
    description: 'An identifier used to identify a specific cellular network subscriiber.',
  },
};

export const entityObservableKeys = Object.values(EntityObservableEnum);

// =======================
// Filter Type
// =======================

export enum FilterEnum {
  // MÉTADONNÉES GÉNÉRALES, CRÉATION ET MISE À JOUR
  CREATED_AT = 'created_at',
  UPDATED_AT = 'updated_at',
  CREATED = 'created',
  CREATOR_ID = 'creator_id',
  CREATEDBY = 'createdBy',
  WORKFLOW_ID = 'workflow_id',
  OBJECTS = 'objects',

  // ÉVALUATIONS, OPINIONS ET SCORING
  OPINIONS_METRICS_MEAN = 'opinions_metrics.mean',
  OPINIONS_METRICS_MAX = 'opinions_metrics.max',
  OPINIONS_METRICS_MIN = 'opinions_metrics.min',
  OPINIONS_METRICS_TOTAL = 'opinions_metrics.total',
  COMPUTED_RELIABILITY = 'computed_reliability',
  CONFIDENCE = 'confidence',
  RATING = 'rating',
  OPINION = 'opinion',
  LIKELIHOOD = 'likelihood',

  // NOM, DESCRIPTION ET CONTENU
  NAME = 'name',
  ALIAS = 'alias',
  DESCRIPTION = 'description',
  ATTRIBUTE_ABSTRACT = 'attribute_abstract',
  CONTENT = 'content',
  NOTE_TYPES = 'note_types',
  EXPLANATION = 'explanation',
  X_OPENCTI_DESCRIPTION = 'x_opencti_description',
  X_OPENCTI_ADDITIONAL_NAMES = 'x_opencti_additional_names',
  MEDIA_CATEGORY = 'media_category',
  TITLE = 'title',
  DISPLAY_NAME = 'display_name',

  // MITRE ATT&CK / TACTIQUES, TECHNIQUES, PROCÉDÉS
  X_MITRE_PLATFORMS = 'x_mitre_platforms',
  X_MITRE_PERMISSIONS_REQUIRED = 'x_mitre_permissions_required',
  X_MITRE_DETECTION = 'x_mitre_detection',
  X_MITRE_ID = 'x_mitre_id',

  // PHASES DE LA KILL CHAIN / RELATIONSHIPS / THREAT HUNTING
  KILL_CHAIN_PHASES = 'killChainPhases',
  X_OPENCTI_THREAT_HUNTING = 'x_opencti_threat_hunting',
  X_OPENCTI_LOG_SOURCES = 'x_opencti_log_sources',

  // OBSERVATIONS, INDICATEURS ET VALIDITÉ
  FIRST_SEEN = 'first_seen',
  LAST_SEEN = 'last_seen',
  FIRST_OBSERVED = 'first_observed',
  LAST_OBSERVED = 'last_observed',
  NUMBER_OBSERVED = 'number_observed',
  VALID_FROM = 'valid_from',
  VALID_UNTIL = 'valid_until',
  PATTERN_TYPE = 'pattern_type',
  PATTERN = 'pattern',
  INDICATOR_TYPES = 'indicator_types',
  CONTAINS_OBSERVABLE = 'containsObservable',
  OBS_CONTENT = 'obsContent',

  // DATES ET PUBLICATION DE RAPPORTS OU NOTES
  PUBLISHED = 'published',
  PUBLICATION_DATE = 'publication_date',
  DATA_SOURCE = 'dataSource',
  COLLECTION_LAYERS = 'collection_layers',
  DUE_DATE = 'due_date',
  SUBMITTED = 'submitted',
  ANALYSIS_STARTED = 'analysis_started',
  ANALYSIS_ENDED = 'analysis_ended',

  // REPORTS, PARTICIPANTS & ORGANIZATIONS
  REPORT_TYPES = 'report_types',
  OBJECT_PARTICIPANT = 'objectParticipant',
  OBJECT_ORGANIZATION = 'objectOrganization',
  CONTACT_INFORMATION = 'contact_information',
  PERSONA_NAME = 'persona_name',
  PERSONA_TYPE = 'persona_type',
  X_OPENCTI_ORGANIZATION_TYPE = 'x_opencti_organization_type',

  // INFRASTRUCTURE / RÉSEAUX
  INFRASTRUCTURE_TYPES = 'infrastructure_types',
  GOALS = 'goals',
  RESOURCE_LEVEL = 'resource_level',
  NETWORK_SRC = 'networkSrc',
  NETWORK_DST = 'networkDst',
  PROTOCOLS = 'protocols',
  SRC_PORT = 'src_port',
  DST_PORT = 'dst_port',
  SRC_BYTE_COUNT = 'src_byte_count',
  DST_BYTE_COUNT = 'dst_byte_count',
  SRC_PACKETS = 'src_packets',
  DST_PACKETS = 'dst_packets',
  SRC_PAYLOAD = 'srcPayload',
  DST_PAYLOAD = 'dstPayload',
  NETWORK_ENCAPSULATES = 'networkEncapsulates',
  ENCAPSULATED_BY = 'encapsulatedBy',

  // MENACES : MALWARE, ACTEURS, OUTILS
  MALWARE_TYPES = 'malware_types',
  IS_FAMILY = 'is_family',
  ARCHITECTURE_EXECUTION_ENVS = 'architecture_execution_envs',
  IMPLEMENTATION_LANGUAGES = 'implementation_languages',
  CAPABILITIES = 'capabilities',
  SAMPLES = 'samples',
  OPERATING_SYSTEMS = 'operatingSystems',
  THREAT_ACTOR_TYPES = 'threat_actor_types',
  ROLES = 'roles',
  SOPHISTICATION = 'sophistication',
  TOOL_TYPES = 'tool_types',
  TOOL_VERSION = 'tool_version',
  PERSONAL_MOTIVATIONS = 'personal_motivations',
  PRIMARY_MOTIVATION = 'primary_motivation',
  SECONDARY_MOTIVATIONS = 'secondary_motivations',

  // VULNÉRABILITÉS / SCORE CVSS / EXPLOITS
  X_OPENCTI_CVSS_BASE_SCORE = 'x_opencti_cvss_base_score',
  X_OPENCTI_CVSS_BASE_SEVERITY = 'x_opencti_cvss_base_severity',
  X_OPENCTI_CVSS_ATTACK_VECTOR = 'x_opencti_cvss_attack_vector',
  X_OPENCTI_CVSS_INTEGRITY_IMPACT = 'x_opencti_cvss_integrity_impact',
  X_OPENCTI_CVSS_AVAILABILITY_IMPACT = 'x_opencti_cvss_availability_impact',
  X_OPENCTI_CVSS_CONFIDENTIALITY_IMPACT = 'x_opencti_cvss_confidentiality_impact',
  X_OPENCTI_CISA_KEV = 'x_opencti_cisa_kev',
  X_OPENCTI_EPSS_SCORE = 'x_opencti_epss_score',
  X_OPENCTI_EPSS_PERCENTILE = 'x_opencti_epss_percentile',

  // AUTRES
  X_OPENCTI_DETECTION = 'x_opencti_detection',
  X_OPENCTI_MAIN_OBSERVABLE_TYPE = 'x_opencti_main_observable_type',
  X_OPENCTI_SCORE = 'x_opencti_score',

  // INCIDENTS, ÉVÉNEMENTS ET SÉVÉRITÉ
  INCIDENT_TYPE = 'incident_type',
  SEVERITY = 'severity',
  SOURCE = 'source',
  CHANNEL_TYPES = 'channel_types',
  EVENT_TYPES = 'event_types',
  START_TIME = 'start_time',
  STOP_TIME = 'stop_time',
  CONTEXT = 'context',
  NARRATIVE_TYPES = 'narrative_types',
  PRIORITY = 'priority',
  RESPONSE_TYPES = 'response_types',
  INFORMATION_TYPES = 'information_types',
  TAKEDOWN_TYPES = 'takedown_types',
  RESULT = 'result',

  // ANALYSES ET CONFIGURATIONS
  CONFIGURATION_VERSION = 'configuration_version',
  MODULES = 'modules',
  ANALYSIS_ENGINE_VERSION = 'analysis_engine_version',
  ANALYSIS_DEFINITION_VERSION = 'analysis_definition_version',
  HOST_VM = 'hostVm',
  ANALYSIS_SCO = 'analysisSco',
  ANALYSIS_SAMPLE = 'analysisSample',
  REVOKED = 'revoked',

  // INFORMATIONS PERSONNELLES OU IDENTITÉ
  DATE_OF_BIRTH = 'date_of_birth',
  GENDER = 'gender',
  JOB_TITLE = 'job_title',
  MARITAL_STATUS = 'marital_status',
  EYE_COLOR = 'eye_color',
  HAIR_COLOR = 'hair_color',
  BORN_IN = 'bornIn',
  ETHNICITY = 'ethnicity',

  // FICHIERS, SYSTÈMES ET PROCESSUS
  PATH = 'path',
  PATH_ENC = 'path_enc',
  CTIME = 'ctime',
  MTIME = 'mtime',
  ATIME = 'atime',
  MIME_TYPE = 'mime_type',
  PAYLOAD_BIN = 'payload_bin',
  SIZE = 'size',
  NAME_ENC = 'name_enc',
  MAGIC_NUMBER_HEX = 'magic_number_hex',
  PARENT_DIRECTORY = 'parentDirectory',
  IS_HIDDEN = 'is_hidden',
  CREATED_TIME = 'created_time',
  CWD = 'cwd',
  COMMAND_LINE = 'command_line',
  ENVIRONMENT_VARIABLES = 'environment_variables',
  ASLR_ENABLED = 'aslr_enabled',
  DEP_ENABLED = 'dep_enabled',
  OWNER_SID = 'owner_sid',
  WINDOW_TITLE = 'window_title',
  INTEGRITY_LEVEL = 'integrity_level',

  // SERVICES ET PROCESSUS AVANCÉS
  SERVICE_NAME = 'service_name',
  DESCRIPTIONS = 'descriptions',
  GROUP_NAME = 'group_name',
  START_TYPE = 'start_type',
  SERVICE_TYPE = 'service_type',
  SERVICE_STATUS = 'service_status',
  OPENED_CONNECTIONS = 'openedConnections',
  CREATOR_USER = 'creatorUser',
  PROCESS_IMAGE = 'processImage',
  PROCESS_PARENT = 'processParent',
  PROCESS_CHILD = 'processChild',
  SERVICE_DLLS = 'serviceDlls',

  // LOGICIEL, VENDOR & CPE
  CPE = 'cpe',
  SWID = 'swid',
  LANGUAGES = 'languages',
  VENDOR = 'vendor',

  // UTILISATEURS, COMPTES ET IDENTIFIANTS
  USER_ID = 'user_id',
  CREDENTIAL = 'credential',
  ACCOUNT_LOGIN = 'account_login',
  ACCOUNT_TYPE = 'account_type',
  IS_SERVICE_ACCOUNT = 'is_service_account',
  IS_PRIVILEGED = 'is_privileged',
  CAN_ESCALATE_PRIVS = 'can_escalate_privs',
  IS_DISABLED = 'is_disabled',
  ACCOUNT_CREATED = 'account_created',
  ACCOUNT_EXPIRES = 'account_expires',
  CREDENTIAL_LAST_CHANGED = 'credential_last_changed',
  ACCOUNT_FIRST_LOGIN = 'account_first_login',
  ACCOUNT_LAST_LOGIN = 'account_last_login',

  // CLÉS ET REGISTRES WINDOWS
  ATTRIBUTE_KEY = 'attribute_key',
  MODIFIED_TIME = 'modified_time',
  NUMBER_OF_SUBKEYS = 'number_of_subkeys',
  WIN_REG_VALUES = 'winRegValues',

  // FINANCES : IBAN, CARTES, COMPTES
  IBAN = 'iban',
  BIC = 'bic',
  ACCOUNT_NUMBER = 'account_number',
  CARD_NUMBER = 'card_number',
  EXPIRATION_DATE = 'expiration_date',
  CVV = 'cvv',
  HOLDER_NAME = 'holder_name',

  // ADRESSES, LIEUX, DIVERS
  POSTAL_CODE = 'postal_code',
  STREET_ADDRESS = 'street_address',

  // EMAILS ET COMMUNICATIONS
  MESSAGE_ID = 'message_id',
  SUBJECT = 'subject',
  RECEIVED_LINES = 'received_lines',
  BODY = 'body',
  EMAIL_FROM = 'emailFrom',
  EMAIL_SENDER = 'emailSender',
  EMAIL_TO = 'emailTo',
  EMAIL_CC = 'emailCc',
  EMAIL_BCC = 'emailBcc',
  BODY_MULTIPART = 'bodyMultipart',
  RAW_EMAIL = 'rawEmail',
  CONTENT_DISPOSITION = 'content_disposition',
  BODY_RAW = 'bodyRaw',

  // HACHAGES ET SIGNATURES
  HASHES_MD5 = 'hashes.MD5',
  HASHES_SHA_1 = 'hashes.SHA-1',
  HASHES_SHA_256 = 'hashes.SHA-256',
  HASHES_SHA_512 = 'hashes.SHA-512',
  HASHES_SSDEEP = 'hashes.SSDEEP',

  // URL ET CRYPTAGE
  URL = 'url',
  ENCRYPTION_ALGORITHM = 'encryption_algorithm',
  DECRYPTION_KEY = 'decryption_key',

  // EXTENSIONS, FICHIERS & NOMS ENCODÉS
  EXTENSIONS = 'extensions',

  // CERTIFICATS / X.509
  IS_SELF_SIGNED = 'is_self_signed',
  SERIAL_NUMBER = 'serial_number',
  SIGNATURE_ALGORITHM = 'signature_algorithm',
  ISSUER = 'issuer',
  VALIDITY_NOT_BEFORE = 'validity_not_before',
  VALIDITY_NOT_AFTER = 'validity_not_after',
  SUBJECT_PUBLIC_KEY_ALGORITHM = 'subject_public_key_algorithm',
  SUBJECT_PUBLIC_KEY_MODULUS = 'subject_public_key_modulus',
  SUBJECT_PUBLIC_KEY_EXPONENT = 'subject_public_key_exponent',
  BASIC_CONSTRAINTS = 'basic_constraints',
  NAME_CONSTRAINTS = 'name_constraints',
  POLICY_CONSTRAINTS = 'policy_constraints',
  KEY_USAGE = 'key_usage',
  EXTENDED_KEY_USAGE = 'extended_key_usage',
  SUBJECT_KEY_IDENTIFIER = 'subject_key_identifier',
  AUTHORITY_KEY_IDENTIFIER = 'authority_key_identifier',
  SUBJECT_ALTERNATIVE_NAME = 'subject_alternative_name',
  ISSUER_ALTERNATIVE_NAME = 'issuer_alternative_name',
  SUBJECT_DIRECTORY_ATTRIBUTES = 'subject_directory_attributes',
  CRL_DISTRIBUTION_POINTS = 'crl_distribution_points',
  INHIBIT_ANY_POLICY = 'inhibit_any_policy',
  PRIVATE_KEY_USAGE_PERIOD_NOT_BEFORE = 'private_key_usage_period_not_before',
  PRIVATE_KEY_USAGE_PERIOD_NOT_AFTER = 'private_key_usage_period_not_after',
  CERTIFICATE_POLICIES = 'certificate_policies',
  POLICY_MAPPINGS = 'policy_mappings',

  // SSHKey
  KEY_PUBLIC = 'key_public',
  KEY_TYPE = 'key_type',
  KEY_LENGTH = 'key_length',
  FINGERPRINT_SHA256 = 'fingerprint_sha256',
  FINGERPRINT_MD5 = 'fingerprint_md5',
  COMMENT = 'comment',

  // INTERVALLES GÉNÉRIQUES (TEMPS, ACTIVITÉ)
  START = 'start',
  END = 'end',
  IS_ACTIVE = 'is_active',

  // PROCESS ID (PID) & AUTRES INFOS SYSTÈME
  PID = 'pid',
  BELONGS_TO = 'belongsTo',

  // AUTRES CHAMPS ET PROPRIÉTÉS
  RIR = 'rir',
  DATA = 'data',
  DATA_TYPE = 'data_type',
  ENTITY_TYPE = 'entity_type',
  REGARDING_OF = 'regardingOf',
  OBJECT_ASSIGNEE = 'objectAssignee',

  // Missing
  OBJECT_LABEL = 'objectLabel',
  OBJECT_MARKING = 'objectMarking',
  EXTERNAL_REFERENCES = 'externalReferences',
  OBJECTIVE = 'objective',
  PRODUCT = 'product',
  VERSION = 'version',
  OPERATING_SYSTEM = 'operatingSystem',
  INSTALLED_SOFTWARE = 'installedSoftware',
  NUMBER = 'number',
  VALUE = 'value',
  RESOLVES_TO = 'resolvesTo',
  IS_MULTIPART = 'is_multipart',
  ATTRIBUTE_DATE = 'attribute_date',
  CONTENT_TYPE = 'content_type',
}

export const filterKeysSmall = [
  FilterEnum.CREATED_AT,
  FilterEnum.UPDATED_AT,
  FilterEnum.CREATED,
  FilterEnum.CREATOR_ID,
  FilterEnum.CREATEDBY,
  FilterEnum.WORKFLOW_ID,
  FilterEnum.OBJECTS,
  FilterEnum.NAME,
  FilterEnum.ALIAS,
  FilterEnum.DESCRIPTION,
  FilterEnum.ATTRIBUTE_ABSTRACT,
  FilterEnum.CONTENT,
  FilterEnum.NOTE_TYPES,
  FilterEnum.X_OPENCTI_DESCRIPTION,
  FilterEnum.X_OPENCTI_ADDITIONAL_NAMES,
  FilterEnum.MEDIA_CATEGORY,
  FilterEnum.TITLE,
  FilterEnum.X_MITRE_PLATFORMS,
  FilterEnum.X_MITRE_DETECTION,
  FilterEnum.X_MITRE_ID,
  FilterEnum.KILL_CHAIN_PHASES,
  FilterEnum.FIRST_SEEN,
  FilterEnum.LAST_SEEN,
  FilterEnum.FIRST_OBSERVED,
  FilterEnum.LAST_OBSERVED,
  FilterEnum.VALID_FROM,
  FilterEnum.VALID_UNTIL,
  FilterEnum.PATTERN_TYPE,
  FilterEnum.PATTERN,
  FilterEnum.INDICATOR_TYPES,
  FilterEnum.PUBLISHED,
  FilterEnum.PUBLICATION_DATE,
  FilterEnum.DUE_DATE,
  FilterEnum.SUBMITTED,
  FilterEnum.ANALYSIS_STARTED,
  FilterEnum.ANALYSIS_ENDED,
  FilterEnum.REPORT_TYPES,
  FilterEnum.OBJECT_PARTICIPANT,
  FilterEnum.OBJECT_ORGANIZATION,
  FilterEnum.PERSONA_NAME,
  FilterEnum.PERSONA_TYPE,
  FilterEnum.X_OPENCTI_ORGANIZATION_TYPE,
  FilterEnum.INFRASTRUCTURE_TYPES,
  FilterEnum.GOALS,
  FilterEnum.RESOURCE_LEVEL,
  FilterEnum.NETWORK_SRC,
  FilterEnum.NETWORK_DST,
  FilterEnum.PROTOCOLS,
  FilterEnum.SRC_PORT,
  FilterEnum.DST_PORT,
  FilterEnum.SRC_PACKETS,
  FilterEnum.DST_PACKETS,
  FilterEnum.SRC_PAYLOAD,
  FilterEnum.DST_PAYLOAD,
  FilterEnum.MALWARE_TYPES,
  FilterEnum.IS_FAMILY,
  FilterEnum.IMPLEMENTATION_LANGUAGES,
  FilterEnum.CAPABILITIES,
  FilterEnum.SAMPLES,
  FilterEnum.OPERATING_SYSTEMS,
  FilterEnum.THREAT_ACTOR_TYPES,
  FilterEnum.ROLES,
  FilterEnum.SOPHISTICATION,
  FilterEnum.TOOL_TYPES,
  FilterEnum.TOOL_VERSION,
  FilterEnum.PERSONAL_MOTIVATIONS,
  FilterEnum.PRIMARY_MOTIVATION,
  FilterEnum.SECONDARY_MOTIVATIONS,
  FilterEnum.X_OPENCTI_CVSS_BASE_SCORE,
  FilterEnum.X_OPENCTI_CVSS_BASE_SEVERITY,
  FilterEnum.X_OPENCTI_CVSS_ATTACK_VECTOR,
  FilterEnum.X_OPENCTI_CVSS_INTEGRITY_IMPACT,
  FilterEnum.X_OPENCTI_CVSS_AVAILABILITY_IMPACT,
  FilterEnum.X_OPENCTI_CVSS_CONFIDENTIALITY_IMPACT,
  FilterEnum.X_OPENCTI_CISA_KEV,
  FilterEnum.X_OPENCTI_EPSS_SCORE,
  FilterEnum.X_OPENCTI_EPSS_PERCENTILE,
  FilterEnum.X_OPENCTI_DETECTION,
  FilterEnum.X_OPENCTI_MAIN_OBSERVABLE_TYPE,
  FilterEnum.X_OPENCTI_SCORE,
  FilterEnum.INCIDENT_TYPE,
  FilterEnum.SEVERITY,
  FilterEnum.SOURCE,
  FilterEnum.CHANNEL_TYPES,
  FilterEnum.EVENT_TYPES,
  FilterEnum.START_TIME,
  FilterEnum.STOP_TIME,
  FilterEnum.PRIORITY,
  FilterEnum.RESPONSE_TYPES,
  FilterEnum.INFORMATION_TYPES,
  FilterEnum.TAKEDOWN_TYPES,
  FilterEnum.RESULT,
  FilterEnum.REVOKED,
  FilterEnum.DATE_OF_BIRTH,
  FilterEnum.GENDER,
  FilterEnum.JOB_TITLE,
  FilterEnum.MARITAL_STATUS,
  FilterEnum.EYE_COLOR,
  FilterEnum.HAIR_COLOR,
  FilterEnum.BORN_IN,
  FilterEnum.ETHNICITY,
  FilterEnum.PATH,
  FilterEnum.SIZE,
  FilterEnum.SERVICE_NAME,
  FilterEnum.DESCRIPTIONS,
  FilterEnum.GROUP_NAME,
  FilterEnum.START_TYPE,
  FilterEnum.SERVICE_TYPE,
  FilterEnum.SERVICE_STATUS,
  FilterEnum.CPE,
  FilterEnum.LANGUAGES,
  FilterEnum.VENDOR,
  FilterEnum.USER_ID,
  FilterEnum.CREDENTIAL,
  FilterEnum.ACCOUNT_LOGIN,
  FilterEnum.ACCOUNT_TYPE,
  FilterEnum.IS_DISABLED,
  FilterEnum.ACCOUNT_CREATED,
  FilterEnum.ACCOUNT_EXPIRES,
  FilterEnum.ACCOUNT_FIRST_LOGIN,
  FilterEnum.ACCOUNT_LAST_LOGIN,
  FilterEnum.ATTRIBUTE_KEY,
  FilterEnum.MODIFIED_TIME,
  FilterEnum.NUMBER_OF_SUBKEYS,
  FilterEnum.IBAN,
  FilterEnum.BIC,
  FilterEnum.ACCOUNT_NUMBER,
  FilterEnum.CARD_NUMBER,
  FilterEnum.EXPIRATION_DATE,
  FilterEnum.CVV,
  FilterEnum.HOLDER_NAME,
  FilterEnum.POSTAL_CODE,
  FilterEnum.STREET_ADDRESS,
  FilterEnum.MESSAGE_ID,
  FilterEnum.SUBJECT,
  FilterEnum.RECEIVED_LINES,
  FilterEnum.BODY,
  FilterEnum.EMAIL_FROM,
  FilterEnum.EMAIL_SENDER,
  FilterEnum.EMAIL_TO,
  FilterEnum.EMAIL_CC,
  FilterEnum.EMAIL_BCC,
  FilterEnum.BODY_MULTIPART,
  FilterEnum.RAW_EMAIL,
  FilterEnum.BODY_RAW,
  FilterEnum.HASHES_MD5,
  FilterEnum.HASHES_SHA_1,
  FilterEnum.HASHES_SHA_256,
  FilterEnum.HASHES_SHA_512,
  FilterEnum.HASHES_SSDEEP,
  FilterEnum.URL,
  FilterEnum.EXTENSIONS,
  FilterEnum.ISSUER,
  FilterEnum.VALIDITY_NOT_BEFORE,
  FilterEnum.VALIDITY_NOT_AFTER,
  FilterEnum.START,
  FilterEnum.END,
  FilterEnum.IS_ACTIVE,
  FilterEnum.PID,
  FilterEnum.RIR,
  FilterEnum.DATA,
  FilterEnum.DATA_TYPE,
  FilterEnum.ENTITY_TYPE,
  FilterEnum.REGARDING_OF,
  FilterEnum.OBJECT_ASSIGNEE,
  FilterEnum.OBJECT_LABEL,
  FilterEnum.OBJECT_MARKING,
  FilterEnum.EXTERNAL_REFERENCES,
  FilterEnum.OBJECTIVE,
  FilterEnum.VERSION,
  FilterEnum.NUMBER,
  FilterEnum.VALUE,
  FilterEnum.CONTENT_TYPE,
  FilterEnum.KEY_TYPE,
  FilterEnum.KEY_PUBLIC,
  FilterEnum.FINGERPRINT_MD5,
  FilterEnum.FINGERPRINT_SHA256,
  FilterEnum.EXPIRATION_DATE,
];
