import { ChatPromptTemplate, FewShotChatMessagePromptTemplate } from '@langchain/core/prompts';
import { z } from 'zod';

/**
 * Creates an array of z.literal instances based on the provided list of filter keys.
 * For each key in the list, the function retrieves the description from FilterObject.
 *
 * @param keys - An array of filter keys.
 * @param filterObj - The FilterObject from which to extract descriptions.
 * @returns An array of z.literal instances with their respective descriptions.
 */
export function createZodLiteralList(filterKeys:any, FilterObject:any) {
  return filterKeys.map((key:any) => {
    // Extract the description from the FilterObject's schema.
    return z.literal(key).describe(FilterObject[key]["description"]);
  });
}

export function createZodLiteralUnion(
  filterKeys:any,
  FilterObject:any,
  unionDescription?:any
): any {
  const literalList = createZodLiteralList(filterKeys, FilterObject);

  // Return appropriate schema based on how many keys were selected
  let resultUnion: any;
  if (literalList.length === 0) {
    resultUnion = z.never();
  } else if (literalList.length === 1) {
    resultUnion = literalList[0];
  } else {
    // z.union requires a tuple with at least two schemas.
    resultUnion = z.union(literalList);
  }

  if (unionDescription) {
    resultUnion = resultUnion.describe(unionDescription);
  }

  return resultUnion;
}


// =======================
// Modes
// =======================

enum ModeEnum {
  AND = "and",
  OR = "or",
}

const ModeObject = {
  [ModeEnum.AND]: {
    type: z.literal(ModeEnum.AND),
    description: "Requires all filter conditions to be met (logical AND).",
  },
  [ModeEnum.OR]: {
    type: z.literal(ModeEnum.OR),
    description:
      "Requires at least one filter condition to be met (logical OR).",
  },
};

export const ModeUnion = createZodLiteralUnion(
  Object.keys(ModeObject),
  ModeObject,
  "The logical mode (or/and) used to filter results."
);

// =======================
// Operators
// =======================

enum OperatorEnum {
  CONTAINS = "contains",
  ENDS_WITH = "ends_with",
  EQ = "eq",
  GT = "gt",
  GTE = "gte",
  LT = "lt",
  LTE = "lte",
  MATCH = "match",
  NIL = "nil",
  NOT_CONTAINS = "not_contains",
  NOT_ENDS_WITH = "not_ends_with",
  NOT_EQ = "not_eq",
  NOT_NIL = "not_nil",
  NOT_STARTS_WITH = "not_starts_with",
  SCRIPT = "script",
  SEARCH = "search",
  STARTS_WITH = "starts_with",
  WILDCARD = "wildcard",
}

const OperatorObject = {
  [OperatorEnum.CONTAINS]: {
    type: z.literal(OperatorEnum.CONTAINS),
    description: "Filters for values that contain the given substring.",
  },
  [OperatorEnum.ENDS_WITH]: {
    type: z.literal(OperatorEnum.ENDS_WITH),
    description: "Filters for values that end with the given substring.",
  },
  [OperatorEnum.EQ]: {
    type: z.literal(OperatorEnum.EQ),
    description: "Filters for values that exactly match the given criterion.",
  },
  [OperatorEnum.GT]: {
    type: z.literal(OperatorEnum.GT),
    description: "Filters for values greater than the given numeric value.",
  },
  [OperatorEnum.GTE]: {
    type: z.literal(OperatorEnum.GTE),
    description:
      "Filters for values greater than or equal to the given numeric value.",
  },
  [OperatorEnum.LT]: {
    type: z.literal(OperatorEnum.LT),
    description: "Filters for values less than the given numeric value.",
  },
  [OperatorEnum.LTE]: {
    type: z.literal(OperatorEnum.LTE),
    description:
      "Filters for values less than or equal to the given numeric value.",
  },
  [OperatorEnum.MATCH]: {
    type: z.literal(OperatorEnum.MATCH),
    description:
      "Filters for values that match a specified pattern (regex or similar).",
  },
  [OperatorEnum.NIL]: {
    type: z.literal(OperatorEnum.NIL),
    description: "Filters for values that are null or missing.",
  },
  [OperatorEnum.NOT_CONTAINS]: {
    type: z.literal(OperatorEnum.NOT_CONTAINS),
    description:
      "Inverse of 'contains'; filters for values not containing the substring.",
  },
  [OperatorEnum.NOT_ENDS_WITH]: {
    type: z.literal(OperatorEnum.NOT_ENDS_WITH),
    description:
      "Inverse of 'ends_with'; filters for values not ending with the substring.",
  },
  [OperatorEnum.NOT_EQ]: {
    type: z.literal(OperatorEnum.NOT_EQ),
    description:
      "Inverse of 'eq'; filters for values that do not match the given criterion.",
  },
  [OperatorEnum.NOT_NIL]: {
    type: z.literal(OperatorEnum.NOT_NIL),
    description: "Filters for values that are not null or missing.",
  },
  [OperatorEnum.NOT_STARTS_WITH]: {
    type: z.literal(OperatorEnum.NOT_STARTS_WITH),
    description:
      "Inverse of 'starts_with'; filters for values not starting with the substring.",
  },
  [OperatorEnum.SCRIPT]: {
    type: z.literal(OperatorEnum.SCRIPT),
    description: "Filters using a custom script or expression.",
  },
  [OperatorEnum.SEARCH]: {
    type: z.literal(OperatorEnum.SEARCH),
    description: "Full-text or specialized search operator.",
  },
  [OperatorEnum.STARTS_WITH]: {
    type: z.literal(OperatorEnum.STARTS_WITH),
    description: "Filters for values that start with the given substring.",
  },
  [OperatorEnum.WILDCARD]: {
    type: z.literal(OperatorEnum.WILDCARD),
    description:
      "Filters for values matching a wildcard pattern (e.g., * or ?).",
  },
};

export const OperatorUnion = createZodLiteralUnion(
  Object.keys(OperatorObject),
  OperatorObject,
  "The operator used to filter results."
);

// =======================
// Relationship
// =======================

enum RelationshipEnum {
  AMPLIFIES = "amplifies",
  ANALYSIS_OF = "analysis-of",
  ATTRIBUTED_TO = "attributed-to",
  AUTHORED_BY = "authored-by",
  BASED_ON = "based-on",
  BEACONS_TO = "beacons-to",
  BELONGS_TO = "belongs-to",
  CHARACTERIZES = "characterizes",
  CITIZEN_OF = "citizen-of",
  COMMUNICATES_WITH = "communicates-with",
  COMPROMISES = "compromises",
  CONSISTS_OF = "consists-of",
  CONTROLS = "controls",
  COOPERATES_WITH = "cooperates-with",
  DELIVERS = "delivers",
  DERIVED_FROM = "derived-from",
  DETECTS = "detects",
  DOWNLOADS = "downloads",
  DROPS = "drops",
  DUPLICATE_OF = "duplicate-of",
  DYNAMIC_ANALYSIS_OF = "dynamic-analysis-of",
  EMPLOYED_BY = "employed-by",
  EXFILTRATES_TO = "exfiltrates-to",
  EXPLOITS = "exploits",
  HAS = "has",
  HOSTS = "hosts",
  IMPERSONATES = "impersonates",
  INDICATES = "indicates",
  INVESTIGATES = "investigates",
  KNOWN_AS = "known-as",
  LOCATED_AT = "located-at",
  MITIGATES = "mitigates",
  NATIONAL_OF = "national-of",
  ORIGINATES_FROM = "originates-from",
  OWNS = "owns",
  PART_OF = "part-of",
  PARTICIPATES_IN = "participates-in",
  PUBLISHES = "publishes",
  RELATED_TO = "related-to",
  REMEDIATES = "remediates",
  REPORTS_TO = "reports-to",
  RESIDES_IN = "resides-in",
  RESOLVES_TO = "resolves-to",
  REVOKED_BY = "revoked-by",
  STATIC_ANALYSIS_OF = "static-analysis-of",
  SUBNARRATIVE_OF = "subnarrative-of",
  SUBTECHNIQUE_OF = "subtechnique-of",
  SUPPORTS = "supports",
  TARGETS = "targets",
  USES = "uses",
  VARIANT_OF = "variant-of",
}

const RelationshipObject = {
  [RelationshipEnum.ATTRIBUTED_TO]: {
    type: z.literal(RelationshipEnum.ATTRIBUTED_TO),
    description: "Indicates attribution to a threat actor or campaign.",
  },
  [RelationshipEnum.EXPLOITS]: {
    type: z.literal(RelationshipEnum.EXPLOITS),
    description: "Indicates exploitation of a vulnerability or target.",
  },
  [RelationshipEnum.HAS]: {
    type: z.literal(RelationshipEnum.HAS),
    description: "Expresses possession or inclusion.",
  },
  [RelationshipEnum.INDICATES]: {
    type: z.literal(RelationshipEnum.INDICATES),
    description: "Suggests an indicator about an entity or relationship.",
  },
  [RelationshipEnum.LOCATED_AT]: {
    type: z.literal(RelationshipEnum.LOCATED_AT),
    description: "Specifies a geographic or physical location.",
  },
  [RelationshipEnum.ORIGINATES_FROM]: {
    type: z.literal(RelationshipEnum.ORIGINATES_FROM),
    description: "Specifies origin or source location.",
  },
  [RelationshipEnum.PART_OF]: {
    type: z.literal(RelationshipEnum.PART_OF),
    description: "Indicates a subcomponent of a bigger entity.",
  },
  [RelationshipEnum.RELATED_TO]: {
    type: z.literal(RelationshipEnum.RELATED_TO),
    description: "Indicates a non-specific relationship between entities.",
  },
  [RelationshipEnum.SUBTECHNIQUE_OF]: {
    type: z.literal(RelationshipEnum.SUBTECHNIQUE_OF),
    description: "Specifies that this is a subtechnique of a broader tactic.",
  },
  [RelationshipEnum.TARGETS]: {
    type: z.literal(RelationshipEnum.TARGETS),
    description:
      "Indicates targeting of an individual, organization, or system.",
  },
  [RelationshipEnum.USES]: {
    type: z.literal(RelationshipEnum.USES),
    description: "Indicates usage of a tool, malware, or technique.",
  },
  [RelationshipEnum.AMPLIFIES]: {
    type: z.literal(RelationshipEnum.AMPLIFIES),
    description: "Increases the impact or effect of another entity.",
  },
  [RelationshipEnum.ANALYSIS_OF]: {
    type: z.literal(RelationshipEnum.ANALYSIS_OF),
    description: "Denotes an analysis performed on another entity.",
  },
  [RelationshipEnum.AUTHORED_BY]: {
    type: z.literal(RelationshipEnum.AUTHORED_BY),
    description: "Identifies the author of an entity or document.",
  },
  [RelationshipEnum.BASED_ON]: {
    type: z.literal(RelationshipEnum.BASED_ON),
    description: "Indicates a foundation or dependency on another entity.",
  },
  [RelationshipEnum.BEACONS_TO]: {
    type: z.literal(RelationshipEnum.BEACONS_TO),
    description:
      "Indicates communication or signaling to a remote destination.",
  },
  [RelationshipEnum.BELONGS_TO]: {
    type: z.literal(RelationshipEnum.BELONGS_TO),
    description: "Indicates membership or ownership by another entity.",
  },
  [RelationshipEnum.CHARACTERIZES]: {
    type: z.literal(RelationshipEnum.CHARACTERIZES),
    description: "Describes distinctive traits or qualities of another entity.",
  },
  [RelationshipEnum.CITIZEN_OF]: {
    type: z.literal(RelationshipEnum.CITIZEN_OF),
    description: "Denotes citizenship or national belonging.",
  },
  [RelationshipEnum.COMMUNICATES_WITH]: {
    type: z.literal(RelationshipEnum.COMMUNICATES_WITH),
    description: "Indicates two entities communicate or exchange data.",
  },
  [RelationshipEnum.COMPROMISES]: {
    type: z.literal(RelationshipEnum.COMPROMISES),
    description: "Indicates compromise or unauthorized access.",
  },
  [RelationshipEnum.CONSISTS_OF]: {
    type: z.literal(RelationshipEnum.CONSISTS_OF),
    description: "Expresses that an entity is composed of other entities.",
  },
  [RelationshipEnum.CONTROLS]: {
    type: z.literal(RelationshipEnum.CONTROLS),
    description: "Denotes control or governance of another entity.",
  },
  [RelationshipEnum.COOPERATES_WITH]: {
    type: z.literal(RelationshipEnum.COOPERATES_WITH),
    description: "Indicates collaborative or cooperative behavior.",
  },
  [RelationshipEnum.DELIVERS]: {
    type: z.literal(RelationshipEnum.DELIVERS),
    description: "Indicates delivery of malware, payload, or content.",
  },
  [RelationshipEnum.DERIVED_FROM]: {
    type: z.literal(RelationshipEnum.DERIVED_FROM),
    description: "Indicates origin from or derivation of another entity.",
  },
  [RelationshipEnum.DETECTS]: {
    type: z.literal(RelationshipEnum.DETECTS),
    description: "Specifies detection or identification of another entity.",
  },
  [RelationshipEnum.DOWNLOADS]: {
    type: z.literal(RelationshipEnum.DOWNLOADS),
    description: "Indicates downloading actions.",
  },
  [RelationshipEnum.DROPS]: {
    type: z.literal(RelationshipEnum.DROPS),
    description: "Indicates deployment or dropping of malware.",
  },
  [RelationshipEnum.DUPLICATE_OF]: {
    type: z.literal(RelationshipEnum.DUPLICATE_OF),
    description: "Indicates duplication or identical copy.",
  },
  [RelationshipEnum.DYNAMIC_ANALYSIS_OF]: {
    type: z.literal(RelationshipEnum.DYNAMIC_ANALYSIS_OF),
    description: "Denotes dynamic analysis conducted on another entity.",
  },
  [RelationshipEnum.EMPLOYED_BY]: {
    type: z.literal(RelationshipEnum.EMPLOYED_BY),
    description: "Indicates employment or working relationship.",
  },
  [RelationshipEnum.EXFILTRATES_TO]: {
    type: z.literal(RelationshipEnum.EXFILTRATES_TO),
    description: "Specifies exfiltration of data to a destination.",
  },
  [RelationshipEnum.HOSTS]: {
    type: z.literal(RelationshipEnum.HOSTS),
    description: "Indicates hosting of content, infrastructure, or malware.",
  },
  [RelationshipEnum.IMPERSONATES]: {
    type: z.literal(RelationshipEnum.IMPERSONATES),
    description: "Indicates impersonation or masquerading.",
  },
  [RelationshipEnum.INVESTIGATES]: {
    type: z.literal(RelationshipEnum.INVESTIGATES),
    description: "Denotes investigative action or inquiry.",
  },
  [RelationshipEnum.KNOWN_AS]: {
    type: z.literal(RelationshipEnum.KNOWN_AS),
    description: "Denotes alternate naming or alias.",
  },
  [RelationshipEnum.MITIGATES]: {
    type: z.literal(RelationshipEnum.MITIGATES),
    description: "Indicates mitigation actions.",
  },
  [RelationshipEnum.NATIONAL_OF]: {
    type: z.literal(RelationshipEnum.NATIONAL_OF),
    description: "Denotes nationality or affiliation with a nation-state.",
  },
  [RelationshipEnum.OWNS]: {
    type: z.literal(RelationshipEnum.OWNS),
    description: "Expresses ownership or possession.",
  },
  [RelationshipEnum.VARIANT_OF]: {
    type: z.literal(RelationshipEnum.VARIANT_OF),
    description: "Specifies variant or related version.",
  },
};

const relationshipKeysSmall = [
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

export const RelationshipUnionSmall = createZodLiteralUnion(
  relationshipKeysSmall,
  RelationshipObject,
  "List of STIX relationship types recognized by OpenCTI."
);

export const RelationshipUnionLarge = createZodLiteralUnion(
  Object.keys(RelationshipObject),
  RelationshipObject,
  "List of STIX relationship types recognized by OpenCTI."
);

// =======================
// Entities & Observables
// =======================

enum EntityObservableEnum {
  // Entity type
  ADMINISTRATIVE_AREA = "Administrative-Area",
  ATTACK_PATTERN = "Attack-Pattern",
  CAMPAIGN = "Campaign",
  CHANNEL = "Channel",
  CITY = "City",
  COUNTRY = "Country",
  COURSE_OF_ACTION = "Course-Of-Action",
  DATA_COMPONENT = "Data-Component",
  DATA_SOURCE = "Data-Source",
  EVENT = "Event",
  FEEDBACK = "Feedback",
  GROUPING = "Grouping",
  INCIDENT = "Incident",
  CASE_INCIDENT = "Case-Incident",
  INDICATOR = "Indicator",
  INDIVIDUAL = "Individual",
  INFRASTRUCTURE = "Infrastructure",
  INTRUSION_SET = "Intrusion-Set",
  LANGUAGE = "Language",
  MALWARE = "Malware",
  MALWARE_ANALYSIS = "Malware-Analysis",
  NARRATIVE = "Narrative",
  NOTE = "Note",
  OBSERVED_DATA = "Observed-Data",
  OPINION = "Opinion",
  ORGANIZATION = "Organization",
  POSITION = "Position",
  REGION = "Region",
  REPORT = "Report",
  STIX_CYBER_OBSERVABLE = "Stix-Cyber-Observable",
  CASE_RFI = "Case-Rfi",
  CASE_RFT = "Case-Rft",
  SECTOR = "Sector",
  SYSTEM = "System",
  TASK = "Task",
  THREAT_ACTOR_GROUP = "Threat-Actor-Group",
  THREAT_ACTOR_INDIVIDUAL = "Threat-Actor-Individual",
  TOOL = "Tool",
  VULNERABILITY = "Vulnerability",
  // Observable type
  ARTIFACT = "Artifact",
  AUTONOMOUS_SYSTEM = "Autonomous-System",
  BANK_ACCOUNT = "Bank-Account",
  CREDENTIAL = "Credential",
  CRYPTOCURRENCY_WALLET = "Cryptocurrency-Wallet",
  CRYPTOGRAPHIC_KEY = "Cryptographic-Key",
  DIRECTORY = "Directory",
  DOMAIN_NAME = "Domain-Name",
  EMAIL_ADDR = "Email-Addr",
  EMAIL_MESSAGE = "Email-Message",
  EMAIL_MIME_PART_TYPE = "Email-Mime-Part-Type",
  STIX_FILE = "StixFile",
  HOSTNAME = "Hostname",
  IPV4_ADDR = "IPv4-Addr",
  IPV6_ADDR = "IPv6-Addr",
  MAC_ADDR = "Mac-Addr",
  MEDIA_CONTENT = "Media-Content",
  MUTEX = "Mutex",
  NETWORK_TRAFFIC = "Network-Traffic",
  PAYMENT_CARD = "Payment-Card",
  PERSONA = "Persona",
  PHONE_NUMBER = "Phone-Number",
  PROCESS = "Process",
  SOFTWARE = "Software",
  TEXT = "Text",
  TRACKING_NUMBER = "Tracking-Number",
  URL = "Url",
  USER_ACCOUNT = "User-Account",
  USER_AGENT = "User-Agent",
  WINDOWS_REGISTRY_KEY = "Windows-Registry-Key",
  WINDOWS_REGISTRY_VALUE_TYPE = "Windows-Registry-Value-Type",
  X509_CERTIFICATE = "X509-Certificate",
}

const EntityObservableObject = {
  // Entity
  [EntityObservableEnum.ADMINISTRATIVE_AREA]: {
    type: z.literal(EntityObservableEnum.ADMINISTRATIVE_AREA),
    description:
      "Geographical or administrative boundary (non-standard STIX, OpenCTI extension).",
  },
  [EntityObservableEnum.ATTACK_PATTERN]: {
    type: z.literal(EntityObservableEnum.ATTACK_PATTERN),
    description: "STIX: TTP describing a malicious technique (MITRE ATT&CK).",
  },
  [EntityObservableEnum.CAMPAIGN]: {
    type: z.literal(EntityObservableEnum.CAMPAIGN),
    description:
      "STIX: A grouping of adversarial activity over a particular timeframe.",
  },
  [EntityObservableEnum.CHANNEL]: {
    type: z.literal(EntityObservableEnum.CHANNEL),
    description:
      "OpenCTI extension: A communication channel (IRC, Telegram, social media, etc.).",
  },
  [EntityObservableEnum.CITY]: {
    type: z.literal(EntityObservableEnum.CITY),
    description: "Geographical city-level object (OpenCTI extension).",
  },
  [EntityObservableEnum.COUNTRY]: {
    type: z.literal(EntityObservableEnum.COUNTRY),
    description: "Geographical country-level object (OpenCTI extension).",
  },
  [EntityObservableEnum.COURSE_OF_ACTION]: {
    type: z.literal(EntityObservableEnum.COURSE_OF_ACTION),
    description:
      "STIX: A recommendation or guidance to prevent or respond to a threat.",
  },
  [EntityObservableEnum.DATA_COMPONENT]: {
    type: z.literal(EntityObservableEnum.DATA_COMPONENT),
    description:
      "Represents a subpart of a data source (common in detection definitions).",
  },
  [EntityObservableEnum.DATA_SOURCE]: {
    type: z.literal(EntityObservableEnum.DATA_SOURCE),
    description:
      "STIX: A source of information used to collect relevant security data.",
  },
  [EntityObservableEnum.EVENT]: {
    type: z.literal(EntityObservableEnum.EVENT),
    description:
      "Generic event (OpenCTI). Could be a significant cybersecurity occurrence.",
  },
  [EntityObservableEnum.FEEDBACK]: {
    type: z.literal(EntityObservableEnum.FEEDBACK),
    description:
      "User feedback or comment about an entity (OpenCTI extension).",
  },
  [EntityObservableEnum.GROUPING]: {
    type: z.literal(EntityObservableEnum.GROUPING),
    description:
      "STIX: A set of objects grouped together for a specific context.",
  },
  [EntityObservableEnum.INCIDENT]: {
    type: z.literal(EntityObservableEnum.INCIDENT),
    description:
      "OpenCTI extension: A cybersecurity incident referencing a security breach.",
  },
  [EntityObservableEnum.CASE_INCIDENT]: {
    type: z.literal(EntityObservableEnum.CASE_INCIDENT),
    description:
      "OpenCTI extension: An incident case used for investigation workflows.",
  },
  [EntityObservableEnum.INDICATOR]: {
    type: z.literal(EntityObservableEnum.INDICATOR),
    description:
      "STIX: A pattern-based detection for suspicious or malicious activity (IOC).",
  },
  [EntityObservableEnum.INDIVIDUAL]: {
    type: z.literal(EntityObservableEnum.INDIVIDUAL),
    description:
      "OpenCTI extension: An individual person relevant to an investigation.",
  },
  [EntityObservableEnum.INFRASTRUCTURE]: {
    type: z.literal(EntityObservableEnum.INFRASTRUCTURE),
    description:
      "STIX: Adversarial or victim infrastructure (servers, domains, etc.).",
  },
  [EntityObservableEnum.INTRUSION_SET]: {
    type: z.literal(EntityObservableEnum.INTRUSION_SET),
    description:
      "STIX: A grouped set of adversarial behaviors, resources, and patterns over time (APT group).",
  },
  [EntityObservableEnum.LANGUAGE]: {
    type: z.literal(EntityObservableEnum.LANGUAGE),
    description:
      "OpenCTI extension: A spoken or programming language relevant to the entity.",
  },
  [EntityObservableEnum.MALWARE]: {
    type: z.literal(EntityObservableEnum.MALWARE),
    description:
      "STIX: Malicious software such as ransomware, trojan, worm, etc.",
  },
  [EntityObservableEnum.MALWARE_ANALYSIS]: {
    type: z.literal(EntityObservableEnum.MALWARE_ANALYSIS),
    description: "STIX: The process or results of analyzing a malware sample.",
  },
  [EntityObservableEnum.NARRATIVE]: {
    type: z.literal(EntityObservableEnum.NARRATIVE),
    description:
      "OpenCTI extension: A narrative or storyline used in reporting.",
  },
  [EntityObservableEnum.NOTE]: {
    type: z.literal(EntityObservableEnum.NOTE),
    description: "STIX: A non-rewritable note containing user commentary.",
  },
  [EntityObservableEnum.OBSERVED_DATA]: {
    type: z.literal(EntityObservableEnum.OBSERVED_DATA),
    description:
      "STIX: Conveys raw information observed on systems or networks (logs, sensor data).",
  },
  [EntityObservableEnum.OPINION]: {
    type: z.literal(EntityObservableEnum.OPINION),
    description: "STIX: A subjective assessment of the information provided.",
  },
  [EntityObservableEnum.ORGANIZATION]: {
    type: z.literal(EntityObservableEnum.ORGANIZATION),
    description:
      "An organization, company, or institution relevant to the CTI context.",
  },
  [EntityObservableEnum.POSITION]: {
    type: z.literal(EntityObservableEnum.POSITION),
    description:
      "A specific job position or role in an organization (OpenCTI extension).",
  },
  [EntityObservableEnum.REGION]: {
    type: z.literal(EntityObservableEnum.REGION),
    description:
      "A broader geographic region (continent, supra-national zone).",
  },
  [EntityObservableEnum.REPORT]: {
    type: z.literal(EntityObservableEnum.REPORT),
    description:
      "STIX: A collection of threat intelligence detailing a set of related objects.",
  },
  [EntityObservableEnum.STIX_CYBER_OBSERVABLE]: {
    type: z.literal(EntityObservableEnum.STIX_CYBER_OBSERVABLE),
    description:
      "STIX: A technical artifact or observable (file, domain, IP address, etc.).",
  },
  [EntityObservableEnum.CASE_RFI]: {
    type: z.literal(EntityObservableEnum.CASE_RFI),
    description:
      "OpenCTI extension: A request for information in an investigation workflow.",
  },
  [EntityObservableEnum.CASE_RFT]: {
    type: z.literal(EntityObservableEnum.CASE_RFT),
    description:
      "OpenCTI extension: A request for takedown in an investigation workflow.",
  },
  [EntityObservableEnum.SECTOR]: {
    type: z.literal(EntityObservableEnum.SECTOR),
    description: "An industry or business sector (finance, telecom, etc.).",
  },
  [EntityObservableEnum.SYSTEM]: {
    type: z.literal(EntityObservableEnum.SYSTEM),
    description:
      "A system or device relevant to an investigation or infrastructure.",
  },
  [EntityObservableEnum.TASK]: {
    type: z.literal(EntityObservableEnum.TASK),
    description:
      "An action item in an operational or investigative workflow (OpenCTI extension).",
  },
  [EntityObservableEnum.THREAT_ACTOR_GROUP]: {
    type: z.literal(EntityObservableEnum.THREAT_ACTOR_GROUP),
    description:
      "STIX: A collective threat actor entity (APT group, cybercriminal gang).",
  },
  [EntityObservableEnum.THREAT_ACTOR_INDIVIDUAL]: {
    type: z.literal(EntityObservableEnum.THREAT_ACTOR_INDIVIDUAL),
    description: "STIX: A single individual threat actor.",
  },
  [EntityObservableEnum.TOOL]: {
    type: z.literal(EntityObservableEnum.TOOL),
    description:
      "STIX: A software tool used by threat actors, possibly dual-use (legitimate or malicious).",
  },
  [EntityObservableEnum.VULNERABILITY]: {
    type: z.literal(EntityObservableEnum.VULNERABILITY),
    description:
      "STIX: A flaw in software or hardware that can be exploited (e.g., CVE).",
  },
  // Observable
  [EntityObservableEnum.ARTIFACT]: {
    type: z.literal(EntityObservableEnum.ARTIFACT),
    description: "A physical or digital object used as evidence or reference.",
  },
  [EntityObservableEnum.AUTONOMOUS_SYSTEM]: {
    type: z.literal(EntityObservableEnum.AUTONOMOUS_SYSTEM),
    description:
      "A collection of IP networks and routers under common administration.",
  },
  [EntityObservableEnum.BANK_ACCOUNT]: {
    type: z.literal(EntityObservableEnum.BANK_ACCOUNT),
    description: "A financial account held at a bank or financial institution.",
  },
  [EntityObservableEnum.CREDENTIAL]: {
    type: z.literal(EntityObservableEnum.CREDENTIAL),
    description:
      "Authentication information such as usernames, passwords, or tokens.",
  },
  [EntityObservableEnum.CRYPTOCURRENCY_WALLET]: {
    type: z.literal(EntityObservableEnum.CRYPTOCURRENCY_WALLET),
    description: "A digital wallet used to store cryptocurrency credentials.",
  },
  [EntityObservableEnum.CRYPTOGRAPHIC_KEY]: {
    type: z.literal(EntityObservableEnum.CRYPTOGRAPHIC_KEY),
    description:
      "A key used in cryptographic operations, such as encryption or digital signatures.",
  },
  [EntityObservableEnum.DIRECTORY]: {
    type: z.literal(EntityObservableEnum.DIRECTORY),
    description: "A file system directory containing files and subdirectories.",
  },
  [EntityObservableEnum.DOMAIN_NAME]: {
    type: z.literal(EntityObservableEnum.DOMAIN_NAME),
    description: "A human-readable address corresponding to an IP address.",
  },
  [EntityObservableEnum.EMAIL_ADDR]: {
    type: z.literal(EntityObservableEnum.EMAIL_ADDR),
    description: "An email address used for communication.",
  },
  [EntityObservableEnum.EMAIL_MESSAGE]: {
    type: z.literal(EntityObservableEnum.EMAIL_MESSAGE),
    description: "An email message object containing metadata and content.",
  },
  [EntityObservableEnum.EMAIL_MIME_PART_TYPE]: {
    type: z.literal(EntityObservableEnum.EMAIL_MIME_PART_TYPE),
    description: "The MIME type of a part within an email message.",
  },
  [EntityObservableEnum.STIX_FILE]: {
    type: z.literal(EntityObservableEnum.STIX_FILE),
    description: "A file object formatted in STIX.",
  },
  [EntityObservableEnum.HOSTNAME]: {
    type: z.literal(EntityObservableEnum.HOSTNAME),
    description: "A host name identifying a device on a network.",
  },
  [EntityObservableEnum.IPV4_ADDR]: {
    type: z.literal(EntityObservableEnum.IPV4_ADDR),
    description: "An IPv4 address.",
  },
  [EntityObservableEnum.IPV6_ADDR]: {
    type: z.literal(EntityObservableEnum.IPV6_ADDR),
    description: "An IPv6 address.",
  },
  [EntityObservableEnum.MAC_ADDR]: {
    type: z.literal(EntityObservableEnum.MAC_ADDR),
    description: "A MAC address used for network interface identification.",
  },
  [EntityObservableEnum.MEDIA_CONTENT]: {
    type: z.literal(EntityObservableEnum.MEDIA_CONTENT),
    description:
      "Digital media content such as images, videos, or audio files.",
  },
  [EntityObservableEnum.MUTEX]: {
    type: z.literal(EntityObservableEnum.MUTEX),
    description:
      "A mutual exclusion object used to manage access to shared resources.",
  },
  [EntityObservableEnum.NETWORK_TRAFFIC]: {
    type: z.literal(EntityObservableEnum.NETWORK_TRAFFIC),
    description: "Data packets or flows representing network traffic.",
  },
  [EntityObservableEnum.PAYMENT_CARD]: {
    type: z.literal(EntityObservableEnum.PAYMENT_CARD),
    description:
      "Credit or debit card information used for financial transactions.",
  },
  [EntityObservableEnum.PERSONA]: {
    type: z.literal(EntityObservableEnum.PERSONA),
    description: "A digital representation of an individual's online identity.",
  },
  [EntityObservableEnum.PHONE_NUMBER]: {
    type: z.literal(EntityObservableEnum.PHONE_NUMBER),
    description: "A telephone number used for contact or communication.",
  },
  [EntityObservableEnum.PROCESS]: {
    type: z.literal(EntityObservableEnum.PROCESS),
    description:
      "An instance of a running program or process in an operating system.",
  },
  [EntityObservableEnum.SOFTWARE]: {
    type: z.literal(EntityObservableEnum.SOFTWARE),
    description: "A software application or system.",
  },
  [EntityObservableEnum.TEXT]: {
    type: z.literal(EntityObservableEnum.TEXT),
    description: "Plain textual content.",
  },
  [EntityObservableEnum.TRACKING_NUMBER]: {
    type: z.literal(EntityObservableEnum.TRACKING_NUMBER),
    description: "A number used to track shipments or other items.",
  },
  [EntityObservableEnum.URL]: {
    type: z.literal(EntityObservableEnum.URL),
    description:
      "A Uniform Resource Locator specifying the address of a resource on the internet.",
  },
  [EntityObservableEnum.USER_ACCOUNT]: {
    type: z.literal(EntityObservableEnum.USER_ACCOUNT),
    description:
      "An account representing a user, used for authentication and access control.",
  },
  [EntityObservableEnum.USER_AGENT]: {
    type: z.literal(EntityObservableEnum.USER_AGENT),
    description:
      "A string representing the client software making a request (e.g., browser, bot).",
  },
  [EntityObservableEnum.WINDOWS_REGISTRY_KEY]: {
    type: z.literal(EntityObservableEnum.WINDOWS_REGISTRY_KEY),
    description:
      "A key in the Windows Registry containing configuration settings.",
  },
  [EntityObservableEnum.WINDOWS_REGISTRY_VALUE_TYPE]: {
    type: z.literal(EntityObservableEnum.WINDOWS_REGISTRY_VALUE_TYPE),
    description:
      "The type of a value in the Windows Registry (e.g., REG_SZ, REG_DWORD).",
  },
  [EntityObservableEnum.X509_CERTIFICATE]: {
    type: z.literal(EntityObservableEnum.X509_CERTIFICATE),
    description: "A digital certificate conforming to the X.509 standard.",
  },
};

export const EntityUnion = createZodLiteralUnion(
  Object.keys(EntityObservableObject),
  EntityObservableObject,
  "List of STIX/OpenCTI entity types recognized by OpenCTI."
);

// =======================
// Filter Regarding OF
// =======================

export const RegaringOfRelationshipSchema = z.object({
  key: z
    .literal("relationship_type")
    .describe(
      "The key of a 'regardingOf' relationship type filter, always 'relationship_type'."
    ),
  values: z
    .array(RelationshipUnionSmall)
    .describe("A list of relationship type filter values."),
});

export const RegaringOfEntityNameSchema = z.object({
  key: z
    .literal("id")
    .describe("The key of a 'regardingOf' entity name filter, always 'id'."),
  values: z.array(z.string()).describe("A list of entity name filter values."),
});

// =======================
// Filter Type
// =======================

export enum FilterEnum {
  // MÉTADONNÉES GÉNÉRALES, CRÉATION ET MISE À JOUR
  CREATED_AT = "created_at",
  UPDATED_AT = "updated_at",
  CREATED = "created",
  CREATOR_ID = "creator_id",
  CREATEDBY = "createdBy",
  WORKFLOW_ID = "workflow_id",
  OBJECTS = "objects",

  // ÉVALUATIONS, OPINIONS ET SCORING
  OPINIONS_METRICS_MEAN = "opinions_metrics.mean",
  OPINIONS_METRICS_MAX = "opinions_metrics.max",
  OPINIONS_METRICS_MIN = "opinions_metrics.min",
  OPINIONS_METRICS_TOTAL = "opinions_metrics.total",
  COMPUTED_RELIABILITY = "computed_reliability",
  CONFIDENCE = "confidence",
  RATING = "rating",
  OPINION = "opinion",
  LIKELIHOOD = "likelihood",

  // NOM, DESCRIPTION ET CONTENU
  NAME = "name",
  ALIAS = "alias",
  DESCRIPTION = "description",
  ATTRIBUTE_ABSTRACT = "attribute_abstract",
  CONTENT = "content",
  NOTE_TYPES = "note_types",
  EXPLANATION = "explanation",
  X_OPENCTI_DESCRIPTION = "x_opencti_description",
  X_OPENCTI_ADDITIONAL_NAMES = "x_opencti_additional_names",
  MEDIA_CATEGORY = "media_category",
  TITLE = "title",
  DISPLAY_NAME = "display_name",

  // MITRE ATT&CK / TACTIQUES, TECHNIQUES, PROCÉDÉS
  X_MITRE_PLATFORMS = "x_mitre_platforms",
  X_MITRE_PERMISSIONS_REQUIRED = "x_mitre_permissions_required",
  X_MITRE_DETECTION = "x_mitre_detection",
  X_MITRE_ID = "x_mitre_id",

  // PHASES DE LA KILL CHAIN / RELATIONSHIPS / THREAT HUNTING
  KILL_CHAIN_PHASES = "killChainPhases",
  X_OPENCTI_THREAT_HUNTING = "x_opencti_threat_hunting",
  X_OPENCTI_LOG_SOURCES = "x_opencti_log_sources",

  // OBSERVATIONS, INDICATEURS ET VALIDITÉ
  FIRST_SEEN = "first_seen",
  LAST_SEEN = "last_seen",
  FIRST_OBSERVED = "first_observed",
  LAST_OBSERVED = "last_observed",
  NUMBER_OBSERVED = "number_observed",
  VALID_FROM = "valid_from",
  VALID_UNTIL = "valid_until",
  PATTERN_TYPE = "pattern_type",
  PATTERN = "pattern",
  INDICATOR_TYPES = "indicator_types",
  CONTAINS_OBSERVABLE = "containsObservable",
  OBS_CONTENT = "obsContent",

  // DATES ET PUBLICATION DE RAPPORTS OU NOTES
  PUBLISHED = "published",
  PUBLICATION_DATE = "publication_date",
  DATA_SOURCE = "dataSource",
  COLLECTION_LAYERS = "collection_layers",
  DUE_DATE = "due_date",
  SUBMITTED = "submitted",
  ANALYSIS_STARTED = "analysis_started",
  ANALYSIS_ENDED = "analysis_ended",

  // REPORTS, PARTICIPANTS & ORGANIZATIONS
  REPORT_TYPES = "report_types",
  OBJECT_PARTICIPANT = "objectParticipant",
  OBJECT_ORGANIZATION = "objectOrganization",
  CONTACT_INFORMATION = "contact_information",
  PERSONA_NAME = "persona_name",
  PERSONA_TYPE = "persona_type",
  X_OPENCTI_ORGANIZATION_TYPE = "x_opencti_organization_type",

  // INFRASTRUCTURE / RÉSEAUX
  INFRASTRUCTURE_TYPES = "infrastructure_types",
  GOALS = "goals",
  RESOURCE_LEVEL = "resource_level",
  NETWORK_SRC = "networkSrc",
  NETWORK_DST = "networkDst",
  PROTOCOLS = "protocols",
  SRC_PORT = "src_port",
  DST_PORT = "dst_port",
  SRC_BYTE_COUNT = "src_byte_count",
  DST_BYTE_COUNT = "dst_byte_count",
  SRC_PACKETS = "src_packets",
  DST_PACKETS = "dst_packets",
  SRC_PAYLOAD = "srcPayload",
  DST_PAYLOAD = "dstPayload",
  NETWORK_ENCAPSULATES = "networkEncapsulates",
  ENCAPSULATED_BY = "encapsulatedBy",

  // MENACES : MALWARE, ACTEURS, OUTILS
  MALWARE_TYPES = "malware_types",
  IS_FAMILY = "is_family",
  ARCHITECTURE_EXECUTION_ENVS = "architecture_execution_envs",
  IMPLEMENTATION_LANGUAGES = "implementation_languages",
  CAPABILITIES = "capabilities",
  SAMPLES = "samples",
  OPERATING_SYSTEMS = "operatingSystems",
  THREAT_ACTOR_TYPES = "threat_actor_types",
  ROLES = "roles",
  SOPHISTICATION = "sophistication",
  TOOL_TYPES = "tool_types",
  TOOL_VERSION = "tool_version",
  PERSONAL_MOTIVATIONS = "personal_motivations",
  PRIMARY_MOTIVATION = "primary_motivation",
  SECONDARY_MOTIVATIONS = "secondary_motivations",

  // VULNÉRABILITÉS / SCORE CVSS / EXPLOITS
  X_OPENCTI_CVSS_BASE_SCORE = "x_opencti_cvss_base_score",
  X_OPENCTI_CVSS_BASE_SEVERITY = "x_opencti_cvss_base_severity",
  X_OPENCTI_CVSS_ATTACK_VECTOR = "x_opencti_cvss_attack_vector",
  X_OPENCTI_CVSS_INTEGRITY_IMPACT = "x_opencti_cvss_integrity_impact",
  X_OPENCTI_CVSS_AVAILABILITY_IMPACT = "x_opencti_cvss_availability_impact",
  X_OPENCTI_CVSS_CONFIDENTIALITY_IMPACT = "x_opencti_cvss_confidentiality_impact",
  X_OPENCTI_CISA_KEV = "x_opencti_cisa_kev",
  X_OPENCTI_EPSS_SCORE = "x_opencti_epss_score",
  X_OPENCTI_EPSS_PERCENTILE = "x_opencti_epss_percentile",
  X_OPENCTI_DETECTION = "x_opencti_detection",
  X_OPENCTI_MAIN_OBSERVABLE_TYPE = "x_opencti_main_observable_type",
  X_OPENCTI_SCORE = "x_opencti_score",

  // INCIDENTS, ÉVÉNEMENTS ET SÉVÉRITÉ
  INCIDENT_TYPE = "incident_type",
  SEVERITY = "severity",
  SOURCE = "source",
  CHANNEL_TYPES = "channel_types",
  EVENT_TYPES = "event_types",
  START_TIME = "start_time",
  STOP_TIME = "stop_time",
  CONTEXT = "context",
  NARRATIVE_TYPES = "narrative_types",
  PRIORITY = "priority",
  RESPONSE_TYPES = "response_types",
  INFORMATION_TYPES = "information_types",
  TAKEDOWN_TYPES = "takedown_types",
  RESULT = "result",

  // ANALYSES ET CONFIGURATIONS
  CONFIGURATION_VERSION = "configuration_version",
  MODULES = "modules",
  ANALYSIS_ENGINE_VERSION = "analysis_engine_version",
  ANALYSIS_DEFINITION_VERSION = "analysis_definition_version",
  HOST_VM = "hostVm",
  ANALYSIS_SCO = "analysisSco",
  ANALYSIS_SAMPLE = "analysisSample",
  REVOKED = "revoked",

  // INFORMATIONS PERSONNELLES OU IDENTITÉ
  DATE_OF_BIRTH = "date_of_birth",
  GENDER = "gender",
  JOB_TITLE = "job_title",
  MARITAL_STATUS = "marital_status",
  EYE_COLOR = "eye_color",
  HAIR_COLOR = "hair_color",
  BORN_IN = "bornIn",
  ETHNICITY = "ethnicity",

  // FICHIERS, SYSTÈMES ET PROCESSUS
  PATH = "path",
  PATH_ENC = "path_enc",
  CTIME = "ctime",
  MTIME = "mtime",
  ATIME = "atime",
  MIME_TYPE = "mime_type",
  PAYLOAD_BIN = "payload_bin",
  SIZE = "size",
  NAME_ENC = "name_enc",
  MAGIC_NUMBER_HEX = "magic_number_hex",
  PARENT_DIRECTORY = "parentDirectory",
  IS_HIDDEN = "is_hidden",
  CREATED_TIME = "created_time",
  CWD = "cwd",
  COMMAND_LINE = "command_line",
  ENVIRONMENT_VARIABLES = "environment_variables",
  ASLR_ENABLED = "aslr_enabled",
  DEP_ENABLED = "dep_enabled",
  OWNER_SID = "owner_sid",
  WINDOW_TITLE = "window_title",
  INTEGRITY_LEVEL = "integrity_level",

  // SERVICES ET PROCESSUS AVANCÉS
  SERVICE_NAME = "service_name",
  DESCRIPTIONS = "descriptions",
  GROUP_NAME = "group_name",
  START_TYPE = "start_type",
  SERVICE_TYPE = "service_type",
  SERVICE_STATUS = "service_status",
  OPENED_CONNECTIONS = "openedConnections",
  CREATOR_USER = "creatorUser",
  PROCESS_IMAGE = "processImage",
  PROCESS_PARENT = "processParent",
  PROCESS_CHILD = "processChild",
  SERVICE_DLLS = "serviceDlls",

  // LOGICIEL, VENDOR & CPE
  CPE = "cpe",
  SWID = "swid",
  LANGUAGES = "languages",
  VENDOR = "vendor",

  // UTILISATEURS, COMPTES ET IDENTIFIANTS
  USER_ID = "user_id",
  CREDENTIAL = "credential",
  ACCOUNT_LOGIN = "account_login",
  ACCOUNT_TYPE = "account_type",
  IS_SERVICE_ACCOUNT = "is_service_account",
  IS_PRIVILEGED = "is_privileged",
  CAN_ESCALATE_PRIVS = "can_escalate_privs",
  IS_DISABLED = "is_disabled",
  ACCOUNT_CREATED = "account_created",
  ACCOUNT_EXPIRES = "account_expires",
  CREDENTIAL_LAST_CHANGED = "credential_last_changed",
  ACCOUNT_FIRST_LOGIN = "account_first_login",
  ACCOUNT_LAST_LOGIN = "account_last_login",

  // CLÉS ET REGISTRES WINDOWS
  ATTRIBUTE_KEY = "attribute_key",
  MODIFIED_TIME = "modified_time",
  NUMBER_OF_SUBKEYS = "number_of_subkeys",
  WIN_REG_VALUES = "winRegValues",

  // FINANCES : IBAN, CARTES, COMPTES
  IBAN = "iban",
  BIC = "bic",
  ACCOUNT_NUMBER = "account_number",
  CARD_NUMBER = "card_number",
  EXPIRATION_DATE = "expiration_date",
  CVV = "cvv",
  HOLDER_NAME = "holder_name",

  // ADRESSES, LIEUX, DIVERS
  POSTAL_CODE = "postal_code",
  STREET_ADDRESS = "street_address",

  // EMAILS ET COMMUNICATIONS
  MESSAGE_ID = "message_id",
  SUBJECT = "subject",
  RECEIVED_LINES = "received_lines",
  BODY = "body",
  EMAIL_FROM = "emailFrom",
  EMAIL_SENDER = "emailSender",
  EMAIL_TO = "emailTo",
  EMAIL_CC = "emailCc",
  EMAIL_BCC = "emailBcc",
  BODY_MULTIPART = "bodyMultipart",
  RAW_EMAIL = "rawEmail",
  CONTENT_DISPOSITION = "content_disposition",
  BODY_RAW = "bodyRaw",

  // HACHAGES ET SIGNATURES
  HASHES_MD5 = "hashes.MD5",
  HASHES_SHA_1 = "hashes.SHA-1",
  HASHES_SHA_256 = "hashes.SHA-256",
  HASHES_SHA_512 = "hashes.SHA-512",
  HASHES_SSDEEP = "hashes.SSDEEP",

  // URL ET CRYPTAGE
  URL = "url",
  ENCRYPTION_ALGORITHM = "encryption_algorithm",
  DECRYPTION_KEY = "decryption_key",

  // EXTENSIONS, FICHIERS & NOMS ENCODÉS
  EXTENSIONS = "extensions",

  // CERTIFICATS / X.509
  IS_SELF_SIGNED = "is_self_signed",
  SERIAL_NUMBER = "serial_number",
  SIGNATURE_ALGORITHM = "signature_algorithm",
  ISSUER = "issuer",
  VALIDITY_NOT_BEFORE = "validity_not_before",
  VALIDITY_NOT_AFTER = "validity_not_after",
  SUBJECT_PUBLIC_KEY_ALGORITHM = "subject_public_key_algorithm",
  SUBJECT_PUBLIC_KEY_MODULUS = "subject_public_key_modulus",
  SUBJECT_PUBLIC_KEY_EXPONENT = "subject_public_key_exponent",
  BASIC_CONSTRAINTS = "basic_constraints",
  NAME_CONSTRAINTS = "name_constraints",
  POLICY_CONSTRAINTS = "policy_constraints",
  KEY_USAGE = "key_usage",
  EXTENDED_KEY_USAGE = "extended_key_usage",
  SUBJECT_KEY_IDENTIFIER = "subject_key_identifier",
  AUTHORITY_KEY_IDENTIFIER = "authority_key_identifier",
  SUBJECT_ALTERNATIVE_NAME = "subject_alternative_name",
  ISSUER_ALTERNATIVE_NAME = "issuer_alternative_name",
  SUBJECT_DIRECTORY_ATTRIBUTES = "subject_directory_attributes",
  CRL_DISTRIBUTION_POINTS = "crl_distribution_points",
  INHIBIT_ANY_POLICY = "inhibit_any_policy",
  PRIVATE_KEY_USAGE_PERIOD_NOT_BEFORE = "private_key_usage_period_not_before",
  PRIVATE_KEY_USAGE_PERIOD_NOT_AFTER = "private_key_usage_period_not_after",
  CERTIFICATE_POLICIES = "certificate_policies",
  POLICY_MAPPINGS = "policy_mappings",

  // INTERVALLES GÉNÉRIQUES (TEMPS, ACTIVITÉ)
  START = "start",
  END = "end",
  IS_ACTIVE = "is_active",

  // PROCESS ID (PID) & AUTRES INFOS SYSTÈME
  PID = "pid",
  BELONGS_TO = "belongsTo",

  // AUTRES CHAMPS ET PROPRIÉTÉS
  RIR = "rir",
  DATA = "data",
  DATA_TYPE = "data_type",
  ENTITY_TYPE = "entity_type",
  REGARDING_OF = "regardingOf",
  OBJECT_ASSIGNEE = "objectAssignee",

  // Missing
  OBJECT_LABEL = "objectLabel",
  OBJECT_MARKING = "objectMarking",
  EXTERNAL_REFERENCES = "externalReferences",
  OBJECTIVE = "objective",
  PRODUCT = "product",
  VERSION = "version",
  OPERATING_SYSTEM = "operatingSystem",
  INSTALLED_SOFTWARE = "installedSoftware",
  NUMBER = "number",
  VALUE = "value",
  RESOLVES_TO = "resolvesTo",
  IS_MULTIPART = "is_multipart",
  ATTRIBUTE_DATE = "attribute_date",
  CONTENT_TYPE = "content_type",
}


// =============================================================================
// === FILTER Subset ============================================================
// =============================================================================

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
];

// =======================
// Filter Regarding OF
// =======================

const RegardingOfFilterItem = z
  .object({
    key: z
      .literal("regardingOf")
      .describe("The key of the 'regardingOf' filter, always 'regardingOf'."),
    values: z
      .array(
        z.union([RegaringOfRelationshipSchema, RegaringOfEntityNameSchema])
      )
      .describe("A list of entity name or relationship type filter values."),
    operator: OperatorUnion,
    mode: ModeUnion,
  })
  .describe(
    "A filter used to further refine entity filtering based on associated entities and/or relationships."
  );

// =======================
// Entities & Observables
// =======================

const EntityTypeFilterItem = z
  .object({
    key: z
      .literal("entity_type")
      .describe("The key of the entity type filter, always 'entity_type'."),
    values: z
      .array(EntityUnion)
      .describe("A list of entity type filter values."),
    operator: OperatorUnion,
    mode: ModeUnion,
  })
  .describe(
    "A filter used to filter entities by their type as defined by the STIX standard."
  );

// =======================
// Filters Keys: Filter keys subset selected by the product
//  without EntityType & RegardingOf
// =======================

const filterKeys = filterKeysSmall.filter(
  (key) => key !== FilterEnum.ENTITY_TYPE && key !== FilterEnum.REGARDING_OF
) as unknown as readonly [FilterEnum, ...FilterEnum[]];

// =======================
// Filter Schema Without Filter Description
// =======================

const GenericFilterItem = z.object({
  key: z.enum(filterKeys).describe("The key of the filter."),
  values: z.array(z.string()).describe("A list of filter values."),
  operator: OperatorUnion,
  mode: ModeUnion,
});

export const OutputSchemaUnion = z.object({
  filters: z
    .array(
      z.union([EntityTypeFilterItem, RegardingOfFilterItem, GenericFilterItem])
    )
    .describe("The list of filters applied to refine the OpenCTI query."),
  mode: ModeUnion,
});

// examples

const jsonFewShotExamples: { _comment: string, input: string, output: unknown }[] = [
  {
    "_comment": "I/ Identification of threat actors by TTP ID (T1082 technique)",
    "input": "Who's is behind this T1082?",
    "output": {
        "mode": "and",
        "filters": [
            {
                "key": "regardingOf",
                "operator": "eq",
                "values": [
                    {
                        "key": "id",
                        "values": [
                            "T1082"
                        ]
                    }
                ],
                "mode": "or"
            },
            {
                "key": "entity_type",
                "operator": "eq",
                "values": [
                    "Threat-Actor-Group",
                    "Threat-Actor-Individual",
                    "Intrusion-Set"
                ],
                "mode": "or"
            }
        ],
        "filterGroups": []
    }
  },
  {
      "_comment": "I/ Identification of threat actors by report or incident",
      "input": "Who are the threats in the PolarEdge ORB report?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "id",
                          "values": [
                              "PolarEdge ORB report"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Intrusion-Set",
                      "Threat-Actor-Group",
                      "Threat-Actor-Individual"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "II/ Targeting and Potential Victims by Relationship (targets)",
      "input": "Which risks are most likely to affect me?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "relationship_type",
                          "values": [
                              "targets"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Threat-Actor-Group",
                      "Threat-Actor-Individual",
                      "Intrusion-Set"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "II/ Targeting and Potential Victims by ID (e.g., Malicious IP)",
      "input": "Which victims and industry sectors are being affected by 134.175.104.84?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "relationship_type",
                          "values": [
                              "targets"
                          ]
                      },
                      {
                          "key": "id",
                          "values": [
                              "134.175.104.84"
                          ]
                      }
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "III/ Relations and Behaviors - Tactics (uses)",
      "input": "How would Cyber Av3ngers carry out an attack on me?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "id",
                          "values": [
                              "Cyber Av3ngers"
                          ]
                      },
                      {
                          "key": "relationship_type",
                          "values": [
                              "uses"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Attack-Pattern"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "IV/ Malware and IOCs Linked to an Actor (uses)",
      "input": "Can you list the malware used by MustardMan?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "id",
                          "values": [
                              "MustardMan"
                          ]
                      },
                      {
                          "key": "relationship_type",
                          "values": [
                              "uses"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Malware"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "IV/ Malware and IOCs Linked to an Actor (without relationship)",
      "input": "Can you list the IOCs linked to APT-C-00 Ocean Lotus?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "id",
                          "values": [
                              "APT-C-00  Ocean Lotus"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Indicator"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "IV/ Malware and IOCs Linked to an Actor (related-to)",
      "input": "Does the file named 'example_file' have any associations with known threat actors or cyber threats?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Threat-Actor-Group",
                      "Threat-Actor-Individual",
                      "Intrusion-Set"
                  ],
                  "mode": "or"
              },
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "relationship_type",
                          "values": [
                              "related-to"
                          ]
                      },
                      {
                          "key": "id",
                          "values": [
                              "example_file"
                          ]
                      }
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "V/ Intelligence Reports and Incidents - Creators or Assignees (creator_id)",
      "input": "What intelligence reports have been released by the Cambridge Group of Clubs?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "creator_id",
                  "operator": "eq",
                  "values": [
                      "Cambridge Group of Clubs"
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Report"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "V/ Intelligence Reports and Incidents - Creators or Assignees (objectAssignee)",
      "input": "Can you list all cybersecurity incidents assigned to John Doe?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Incident"
                  ],
                  "mode": "or"
              },
              {
                  "key": "objectAssignee",
                  "operator": "eq",
                  "values": [
                      "John Doe"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "VI/ Diversification of Entities (here Vulnerabilities related to a TTP) (Attack-Pattern, Intrusion-Set, Malware, Indicator, Incident, Threat-Actor, Campaign (ny), Course-of-Action (ny), Tool (ny), Vulnerability, Report)",
      "input": "What vulnerabilities are associated with T1497?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {"key": "id", "values": ["T1497"]}
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": ["Vulnerability"],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "VII/ Diversity of Relationships (targets - Victims or industry sectors targeted by an IP) (uses, targets, related-to, located-at)",
      "input": "Which victims and industry sectors are targeted by 134.175.104.84?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {"key": "relationship_type", "values": ["targets"]},
                      {"key": "id", "values": ["134.175.104.84"]}
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "VII/ Diversity of Relationships (located-at - Geolocation of threat actors) (uses, targets, related-to, located-at, mitigates(ny), indicates(ny), compromises(ny))",
      "input": "Which actors are located in Russia?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {"key": "relationship_type", "values": ["located-at"]},
                      {"key": "id", "values": ["Russia"]}
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Threat-Actor-Group",
                      "Threat-Actor-Individual",
                      "Intrusion-Set"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "VIII/ General and Non-CTI Questions (returns empty filters)",
      "input": "What is the impact of quantum computing on encryption?",
      "output": {"mode": "and", "filters": [], "filterGroups": []}
  },
  {
      "_comment": "VIII/ Grammatical and Linguistic Complexity (should return nothing as it's non-CTI)",
      "input": "The sun, a radiant beacon in the sky, spread its golden warmth across the horizon, igniting the dawn with an explosion of brilliant color.",
      "output": {"mode": "and", "filters": [], "filterGroups": []}
  },
  {
      "_comment": "IX/ Complex Questions and Linguistic Complexity: Passive Voice - Conditional Statements - TODO: Support conditional logic",
      "input": "If T1497 was involved, who would be responsible?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "id",
                          "values": [
                              "T1497"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Threat-Actor-Group",
                      "Threat-Actor-Individual",
                      "Intrusion-Set"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "IX/ Complex Questions and Linguistic Complexity: Indirect Questions - TODO: Interpret indirect questions",
      "input": "I wonder who is behind T1497.",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "id",
                          "values": [
                              "T1497"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Threat-Actor-Group",
                      "Threat-Actor-Individual",
                      "Intrusion-Set"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "IX/ Complex Questions and Linguistic Complexity: Logical Operators - TODO: Improve handling of logical operators (AND, OR)",
      "input": "Who uses either T1497 or T1082?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "id",
                          "values": [
                              "T1497"
                          ]
                      },
                      {
                          "key": "id",
                          "values": [
                              "T1082"
                          ]
                      },
                      {
                          "key": "relationship_type",
                          "values": [
                              "uses"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Threat-Actor-Group",
                      "Threat-Actor-Individual",
                      "Intrusion-Set"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "",
      "input": "What are the vulnerabilities related with google?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "id",
                          "values": [
                              "google"
                          ]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": [
                      "Vulnerability"
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "",
      "input": "Show me vulnerabilities with a CVSS score > 10.",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "x_opencti_cvss_base_score",
                  "values": ["10"],
                  "operator": "gt",
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "values": ["Vulnerability"],
                  "operator": "eq",
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "",
      "input": "Show me all reports labeled as TLP:GREEN and TLP:WHITE.",
      "output": {
        "mode": "and",
        "filters": [
          {
            "key": "objectMarking",
            "values": ["TLP:GREEN", "TLP:WHITE"],
            "operator": "eq",
            "mode": "or"
          },
          {
            "key": "entity_type",
            "values": ["Report"],
            "operator": "eq",
            "mode": "or"
          }
        ],
        "filterGroups": []
      }
    },
  {
      "_comment": "",
      "input": "Retrieve all entities tagged with label 'apt50'.",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "objectLabel",
                  "values": ["apt50"],
                  "operator": "eq",
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "",
      "input": "Find all geographical regions.",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "entity_type",
                  "values": ["Region"],
                  "operator": "eq",
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "",
      "input": "Tell me everything you have on fancy bear.",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "name",
                  "operator": "eq",
                  "values": ["fancy bear"],
                  "mode": "or"
              },
              {
                  "key": "alias",
                  "operator": "eq",
                  "values": ["fancy bear"],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "",
      "input": "Who are the victims of APT28 in Europe?",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "relationship_type",
                          "values": ["targets"]
                      },
                      {
                          "key": "id",
                          "values": ["APT28"]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "relationship_type",
                          "values": ["located-at"]
                      },
                      {
                          "key": "id",
                          "values": ["Europe"]
                      }
                  ],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "",
      "input": "Which threats are targeting the Healthcare sector?",
      "output": {
        "mode": "and",
        "filters": [
          {
            "key": "entity_type",
            "operator": "eq",
            "values": [
              "Threat-Actor-Group",
              "Threat-Actor-Individual",
              "Intrusion-Set"
            ],
            "mode": "or"
          },
          {
            "key": "regardingOf",
            "operator": "eq",
            "values": [
              {
                "key": "relationship_type",
                "values": ["targets"]
              },
              {
                "key": "id",
                "values": ["Healthcare"]
              }
            ],
            "mode": "or"
          }
        ],
        "filterGroups": []
      }
  },
  {
      "_comment": "",
      "input": "Show all incident responses assigned to Marc Martin.",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": ["Case-Incident"],
                  "mode": "or"
              },
              {
                  "key": "objectAssignee",
                  "operator": "eq",
                  "values": ["Marc Martin"],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  },
  {
      "_comment": "",
      "input": "Find all incidents linked to APT28.",
      "output": {
          "mode": "and",
          "filters": [
              {
                  "key": "regardingOf",
                  "operator": "eq",
                  "values": [
                      {
                          "key": "id",
                          "values": ["APT28"]
                      }
                  ],
                  "mode": "or"
              },
              {
                  "key": "entity_type",
                  "operator": "eq",
                  "values": ["Incident"],
                  "mode": "or"
              }
          ],
          "filterGroups": []
      }
  }
];

const examples = jsonFewShotExamples.map((item) => ({
  input: item.input,
  output: JSON.stringify(OutputSchemaUnion.safeParse(item.output)).replace(/"/g, "'")
}));

const examplePrompt = ChatPromptTemplate.fromMessages([
  ['human', '{input}'],
  ['ai', '{output}'],
]);

// prompts

const fewShotPrompt = new FewShotChatMessagePromptTemplate({
  examplePrompt,
  examples,
  inputVariables: [],
});

const systemPrompt = "You are an expert in Cyber Threat Intelligence (CTI) and OpenCTI query filters.\nYour role is to extract OpenCTI filters from a user input to query entities in the OpenCTI database.\n\n## Guidelines\n\n### 1. Extract Relevant Filters:\n- Identify key terms in the user input and map them to the correct OpenCTI filters.\n\n### 2. Schema:\n- Always return valid JSON that strictly conforms to the provided Output Schema.\n- Structure:\n  {{\n    \"mode\": \"and\" | \"or\",\n    \"filters\": [\n      {{\n        \"key\": \"string\",\n        \"values\": \"array\",\n        \"operator\": \"eq\" | \"contains\" | \"starts_with\" | ...,\n        \"mode\": \"and\" | \"or\"\n      }}\n    ],\n    \"filterGroups\": []\n  }}\n\n### 3. No Extra Text:\n- Do not return any explanation or commentary outside the JSON.\n\n### 4. STIX / OpenCTI Entities & Relationships:\n- If the user mentions known STIX entities (e.g., 'Malware', 'Threat-Actor'), use \"entity_type\".\n- If the user references relationships (e.g., 'uses', 'targets', 'located-at'), use \"relationship_type\".\n\n### 5. Context Awareness:\n\n#### Ensure the **correct `entity_type`** is always included based on context:\n- **Incident Responses:** {{ \"key\": \"entity_type\", \"values\": [\"Case-Incident\"] }}\n- **Vulnerabilities:** {{ \"key\": \"entity_type\", \"values\": [\"Vulnerability\"] }}\n- **IPV4 Addresses:** {{ \"key\": \"entity_type\", \"values\": [\"IPv4-Addr\"] }}\n- **Threat Actors:** {{ \"key\": \"entity_type\", \"values\": [\"Threat-Actor-Group\", \"Threat-Actor-Individual\", \"Intrusion-Set\"] }}\n- **Reports:** {{ \"key\": \"entity_type\", \"values\": [\"Report\"] }}\n- **Incidents:** {{ \"key\": \"entity_type\", \"values\": [\"Incident\"] }}\n\n#### If filtering vulnerabilities based on CVSS score:\n- Always use `x_opencti_cvss_base_score` and ensure:\n  {{\n    \"key\": \"entity_type\",\n    \"values\": [\"Vulnerability\"],\n    \"operator\": \"eq\",\n    \"mode\": \"or\"\n  }}\n\n#### If filtering data by TLP classification (e.g., \"TLP:RED\", \"TLP:AMBER\"):\n- Ensure the **correct entity type is included**:\n  - \"entity_type\": [\"Incident\"] for incidents.\n  - \"entity_type\": [\"Report\"] for reports.\n\n#### If filtering for threats targeting a specific sector (e.g., Healthcare, Defense):\n- Use:\n  {{\n    \"key\": \"regardingOf\",\n    \"operator\": \"eq\",\n    \"values\": [\n      {{ \"key\": \"relationship_type\", \"values\": [\"targets\"] }},\n      {{ \"key\": \"id\", \"values\": [\"Healthcare\"] }}\n    ]\n  }}\n\n#### When retrieving information about a specific entity (e.g., \"APT28\"):\n- **Only use `name` and `alias`**, and **do not use `regardingOf`** to avoid unrelated results.\n- **Correct format**:\n  {{\n    \"key\": \"name\",\n    \"values\": [\"APT28\"],\n    \"operator\": \"eq\",\n    \"mode\": \"or\"\n  }}\n  {{\n    \"key\": \"alias\",\n    \"values\": [\"APT28\"],\n    \"operator\": \"eq\",\n    \"mode\": \"or\"\n  }}\n- **Do not add `entity_type` when searching by name or alias**.\n\n#### When retrieving victims of a threat:\n- **Do NOT specify `entity_type`** to allow flexibility in victim types.\n- **Correct format:**\n  {{\n    \"key\": \"regardingOf\",\n    \"operator\": \"eq\",\n    \"values\": [\n      {{ \"key\": \"relationship_type\", \"values\": [\"targets\"] }},\n      {{ \"key\": \"id\", \"values\": [\"emotet\"] }}\n    ]\n  }}\n- **Avoid adding `entity_type` to prevent limiting possible victim types**.\n\n#### When retrieving attack patterns used by a threat:\n- Always include `\"relationship_type\": \"uses\"`.\n   - If the input mentions a creator, assignee, or organization, apply creator_id or objectAssignee.\n- **Correct format:**\n  {{\n    \"key\": \"regardingOf\",\n    \"operator\": \"eq\",\n    \"values\": [\n      {{ \"key\": \"relationship_type\", \"values\": [\"uses\"] }},\n      {{ \"key\": \"id\", \"values\": [\"APT28\"] }}\n    ]\n  }}\n- **Ensure `relationship_type: \"uses\"` is always present**.\n\n### 6. Non-CTI Queries:\n- If it's not CTI-related, return:\n  {{\n    \"mode\": \"and\",\n    \"filters\": [],\n    \"filterGroups\": []\n  }}\n";

export const NLQPromptTemplate = ChatPromptTemplate.fromMessages([
  ['system', systemPrompt],
  fewShotPrompt as unknown as ChatPromptTemplate,
  ['human', '{text}'],
]);
