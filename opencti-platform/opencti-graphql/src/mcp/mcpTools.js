import { graphql } from 'graphql';
import { z } from 'zod';

// ---------------------------------------------------------------------------
// Observable type mapping for creation
// Maps: display type → { varName, inputType, fieldName }
// ---------------------------------------------------------------------------

const OBSERVABLE_TYPES = {
  'Autonomous-System': { varName: 'AutonomousSystem', inputType: 'AutonomousSystemAddInput', fieldName: 'number' },
  Directory: { varName: 'Directory', inputType: 'DirectoryAddInput', fieldName: 'path' },
  'Domain-Name': { varName: 'DomainName', inputType: 'DomainNameAddInput', fieldName: 'value' },
  'Email-Addr': { varName: 'EmailAddr', inputType: 'EmailAddrAddInput', fieldName: 'value' },
  Hostname: { varName: 'Hostname', inputType: 'HostnameAddInput', fieldName: 'value' },
  'IPv4-Addr': { varName: 'IPv4Addr', inputType: 'IPv4AddrAddInput', fieldName: 'value' },
  'IPv6-Addr': { varName: 'IPv6Addr', inputType: 'IPv6AddrAddInput', fieldName: 'value' },
  'Mac-Addr': { varName: 'MacAddr', inputType: 'MacAddrAddInput', fieldName: 'value' },
  'Phone-Number': { varName: 'PhoneNumber', inputType: 'PhoneNumberAddInput', fieldName: 'value' },
  StixFile: { varName: 'StixFile', inputType: 'StixFileAddInput', fieldName: 'name' },
  Url: { varName: 'Url', inputType: 'UrlAddInput', fieldName: 'value' },
  'User-Agent': { varName: 'UserAgent', inputType: 'UserAgentAddInput', fieldName: 'value' },
  Credential: { varName: 'Credential', inputType: 'CredentialAddInput', fieldName: 'value' },
  'Cryptocurrency-Wallet': { varName: 'CryptocurrencyWallet', inputType: 'CryptocurrencyWalletAddInput', fieldName: 'value' },
  'Cryptographic-Key': { varName: 'CryptographicKey', inputType: 'CryptographicKeyAddInput', fieldName: 'value' },
  'Tracking-Number': { varName: 'TrackingNumber', inputType: 'TrackingNumberAddInput', fieldName: 'value' },
  Text: { varName: 'Text', inputType: 'TextAddInput', fieldName: 'value' },
  Software: { varName: 'Software', inputType: 'SoftwareAddInput', fieldName: 'name' },
  'Bank-Account': { varName: 'BankAccount', inputType: 'BankAccountAddInput', fieldName: 'iban' },
  Mutex: { varName: 'Mutex', inputType: 'MutexAddInput', fieldName: 'name' },
};

// ---------------------------------------------------------------------------
// STIX pattern mapping for automatic indicator pattern generation
// ---------------------------------------------------------------------------

const STIX_PATTERN_MAP = {
  'IPv4-Addr': { scoType: 'ipv4-addr', prop: 'value', isInt: false },
  'IPv6-Addr': { scoType: 'ipv6-addr', prop: 'value', isInt: false },
  'Domain-Name': { scoType: 'domain-name', prop: 'value', isInt: false },
  Url: { scoType: 'url', prop: 'value', isInt: false },
  'Email-Addr': { scoType: 'email-addr', prop: 'value', isInt: false },
  'Mac-Addr': { scoType: 'mac-addr', prop: 'value', isInt: false },
  Hostname: { scoType: 'hostname', prop: 'value', isInt: false },
  'User-Agent': { scoType: 'user-agent', prop: 'value', isInt: false },
  Credential: { scoType: 'credential', prop: 'value', isInt: false },
  'Phone-Number': { scoType: 'phone-number', prop: 'value', isInt: false },
  'Cryptocurrency-Wallet': { scoType: 'cryptocurrency-wallet', prop: 'value', isInt: false },
  'Cryptographic-Key': { scoType: 'cryptographic-key', prop: 'value', isInt: false },
  'Tracking-Number': { scoType: 'tracking-number', prop: 'value', isInt: false },
  Text: { scoType: 'text', prop: 'value', isInt: false },
  Mutex: { scoType: 'mutex', prop: 'name', isInt: false },
  Directory: { scoType: 'directory', prop: 'path', isInt: false },
  Software: { scoType: 'software', prop: 'name', isInt: false },
  StixFile: { scoType: 'file', prop: 'name', isInt: false },
  'Autonomous-System': { scoType: 'autonomous-system', prop: 'number', isInt: true },
  'Bank-Account': { scoType: 'bank-account', prop: 'iban', isInt: false },
};

const HASH_ALGORITHMS = {
  MD5: 'hashes.MD5',
  'SHA-1': "hashes.'SHA-1'",
  SHA1: "hashes.'SHA-1'",
  'SHA-256': "hashes.'SHA-256'",
  SHA256: "hashes.'SHA-256'",
  'SHA-512': "hashes.'SHA-512'",
  SHA512: "hashes.'SHA-512'",
  SSDEEP: 'hashes.SSDEEP',
};

// ---------------------------------------------------------------------------
// Container-type mutation mapping
// ---------------------------------------------------------------------------

const CONTAINER_MUTATIONS = {
  Report: { mutationName: 'reportAdd', inputType: 'ReportAddInput' },
  'Case-Incident': { mutationName: 'caseIncidentAdd', inputType: 'CaseIncidentAddInput' },
  'Case-Rfi': { mutationName: 'caseRfiAdd', inputType: 'CaseRfiAddInput' },
  'Case-Rft': { mutationName: 'caseRftAdd', inputType: 'CaseRftAddInput' },
  Grouping: { mutationName: 'groupingAdd', inputType: 'GroupingAddInput' },
};

// ---------------------------------------------------------------------------
// SDO-type mutation mapping for generic domain object creation
// ---------------------------------------------------------------------------

const SDO_MUTATIONS = {
  'Threat-Actor-Group': { mutationName: 'threatActorGroupAdd', inputType: 'ThreatActorGroupAddInput' },
  'Threat-Actor-Individual': { mutationName: 'threatActorIndividualAdd', inputType: 'ThreatActorIndividualAddInput' },
  'Intrusion-Set': { mutationName: 'intrusionSetAdd', inputType: 'IntrusionSetAddInput' },
  Campaign: { mutationName: 'campaignAdd', inputType: 'CampaignAddInput' },
  Malware: { mutationName: 'malwareAdd', inputType: 'MalwareAddInput' },
  Tool: { mutationName: 'toolAdd', inputType: 'ToolAddInput' },
  'Attack-Pattern': { mutationName: 'attackPatternAdd', inputType: 'AttackPatternAddInput' },
  Vulnerability: { mutationName: 'vulnerabilityAdd', inputType: 'VulnerabilityAddInput' },
  Incident: { mutationName: 'incidentAdd', inputType: 'IncidentAddInput' },
  Infrastructure: { mutationName: 'infrastructureAdd', inputType: 'InfrastructureAddInput' },
  'Course-Of-Action': { mutationName: 'courseOfActionAdd', inputType: 'CourseOfActionAddInput' },
  Channel: { mutationName: 'channelAdd', inputType: 'ChannelAddInput' },
  Narrative: { mutationName: 'narrativeAdd', inputType: 'NarrativeAddInput' },
  Event: { mutationName: 'eventAdd', inputType: 'EventAddInput' },
  Individual: { mutationName: 'individualAdd', inputType: 'IndividualAddInput' },
  Organization: { mutationName: 'organizationAdd', inputType: 'OrganizationAddInput' },
  Sector: { mutationName: 'sectorAdd', inputType: 'SectorAddInput' },
};

// ---------------------------------------------------------------------------
// GraphQL fragments
// ---------------------------------------------------------------------------

const BASE_FIELDS = `
    id
    entity_type
    standard_id
    parent_types
    created_at
    updated_at
`;

const SDO_INLINE_FIELDS = `
    ... on StixDomainObject {
        created
        modified
        revoked
        confidence
        objectLabel { id value color }
        objectMarking {
            id standard_id definition_type definition
            x_opencti_order x_opencti_color
        }
        createdBy { ... on Identity { id name entity_type } }
        externalReferences {
            edges { node { id source_name url description external_id } }
        }
    }
    ... on AttackPattern { name description aliases x_mitre_id x_mitre_platforms killChainPhases { id kill_chain_name phase_name x_opencti_order } }
    ... on Campaign { name description aliases first_seen last_seen objective }
    ... on CourseOfAction { name description x_opencti_aliases }
    ... on DataComponent { name description }
    ... on DataSource { name description x_mitre_platforms collection_layers }
    ... on Event { name description aliases event_types }
    ... on Channel { name description aliases channel_types }
    ... on Grouping { name description context }
    ... on Incident { name description aliases first_seen last_seen severity objective }
    ... on Indicator {
        name description pattern pattern_type pattern_version
        valid_from valid_until x_opencti_score x_opencti_detection
        indicator_types x_opencti_main_observable_type
        killChainPhases { id kill_chain_name phase_name x_opencti_order }
    }
    ... on Infrastructure { name description aliases infrastructure_types first_seen last_seen }
    ... on IntrusionSet {
        name description aliases first_seen last_seen goals
        resource_level primary_motivation secondary_motivations
    }
    ... on Malware {
        name description aliases malware_types is_family first_seen last_seen
        architecture_execution_envs implementation_languages capabilities
        killChainPhases { id kill_chain_name phase_name x_opencti_order }
    }
    ... on MalwareAnalysis { product version result_name result analysis_started analysis_ended submitted }
    ... on Narrative { name description aliases narrative_types }
    ... on Note { attribute_abstract content authors note_types likelihood }
    ... on ObservedData { first_observed last_observed number_observed }
    ... on Opinion { explanation authors opinion }
    ... on Report { name description report_types published }
    ... on ThreatActor {
        name description aliases threat_actor_types first_seen last_seen
        roles goals sophistication resource_level
        primary_motivation secondary_motivations personal_motivations
    }
    ... on Tool { name description aliases tool_types tool_version killChainPhases { id kill_chain_name phase_name x_opencti_order } }
    ... on Vulnerability {
        name description x_opencti_cvss_base_score
        x_opencti_cvss_base_severity x_opencti_cvss_attack_vector
        x_opencti_epss_score x_opencti_epss_percentile
        x_opencti_cisa_kev x_opencti_cwe x_opencti_score
    }
    ... on Individual { name description x_opencti_aliases contact_information x_opencti_firstname x_opencti_lastname }
    ... on Organization { name description x_opencti_aliases contact_information x_opencti_organization_type x_opencti_reliability }
    ... on Sector { name description x_opencti_aliases contact_information }
    ... on System { name description x_opencti_aliases }
    ... on City { name description latitude longitude x_opencti_aliases }
    ... on Country { name description latitude longitude x_opencti_aliases }
    ... on Region { name description latitude longitude x_opencti_aliases }
    ... on Position { name description latitude longitude street_address postal_code x_opencti_aliases }
    ... on Case { name description }
`;

const SCO_INLINE_FIELDS = `
    ... on StixCyberObservable {
        observable_value x_opencti_score x_opencti_description
        objectLabel { id value color }
        objectMarking { id standard_id definition_type definition x_opencti_order x_opencti_color }
        createdBy { ... on Identity { id name entity_type } }
    }
    ... on AutonomousSystem { number sco_name: name rir }
    ... on Directory { path path_enc ctime mtime atime }
    ... on DomainName { value }
    ... on EmailAddr { value display_name }
    ... on EmailMessage { is_multipart attribute_date content_type message_id subject body }
    ... on Artifact { mime_type url hashes { algorithm hash } }
    ... on StixFile { extensions size sco_name: name name_enc magic_number_hex mime_type hashes { algorithm hash } x_opencti_additional_names }
    ... on IPv4Addr { value }
    ... on IPv6Addr { value }
    ... on MacAddr { value }
    ... on Hostname { value }
    ... on Url { value }
    ... on UserAgent { value }
    ... on PhoneNumber { value }
    ... on Credential { value }
    ... on CryptocurrencyWallet { value }
    ... on CryptographicKey { value }
    ... on TrackingNumber { value }
    ... on Text { value }
    ... on BankAccount { iban bic account_number }
    ... on PaymentCard { card_number expiration_date holder_name }
    ... on Persona { persona_name persona_type }
    ... on MediaContent { title media_content: content url media_category publication_date }
    ... on Mutex { sco_name: name }
    ... on NetworkTraffic { start end is_active src_port dst_port protocols }
    ... on Process { is_hidden pid created_time cwd command_line }
    ... on Software { sco_name: name cpe vendor version }
    ... on UserAccount { user_id account_login account_type display_name is_service_account is_privileged }
    ... on WindowsRegistryKey { attribute_key modified_time }
    ... on X509Certificate { serial_number issuer subject validity_not_before validity_not_after hashes { algorithm hash } }
`;

const ENTITY_FIELDS = BASE_FIELDS + SDO_INLINE_FIELDS + SCO_INLINE_FIELDS;
const SDO_ENTITY_FIELDS = BASE_FIELDS + SDO_INLINE_FIELDS;
const SCO_ENTITY_FIELDS = BASE_FIELDS + SCO_INLINE_FIELDS;

const RELATIONSHIP_FIELDS = `
    id entity_type standard_id relationship_type description
    start_time stop_time revoked confidence created modified created_at updated_at
    objectLabel { id value color }
    objectMarking { id standard_id definition_type definition x_opencti_order x_opencti_color }
    createdBy { ... on Identity { id name entity_type } }
    from {
        ... on BasicObject { id entity_type parent_types }
        ... on StixObject { standard_id }
        ... on AttackPattern { name } ... on Campaign { name } ... on CourseOfAction { name }
        ... on Individual { name } ... on Organization { name } ... on Sector { name } ... on System { name }
        ... on Indicator { name } ... on Infrastructure { name } ... on IntrusionSet { name }
        ... on Position { name } ... on City { name } ... on Country { name } ... on Region { name }
        ... on Malware { name } ... on ThreatActor { name } ... on Tool { name } ... on Vulnerability { name }
        ... on Incident { name } ... on Event { name } ... on Channel { name } ... on Narrative { name }
        ... on DataComponent { name } ... on DataSource { name } ... on Case { name }
        ... on StixCyberObservable { observable_value }
    }
    to {
        ... on BasicObject { id entity_type parent_types }
        ... on StixObject { standard_id }
        ... on AttackPattern { name } ... on Campaign { name } ... on CourseOfAction { name }
        ... on Individual { name } ... on Organization { name } ... on Sector { name } ... on System { name }
        ... on Indicator { name } ... on Infrastructure { name } ... on IntrusionSet { name }
        ... on Position { name } ... on City { name } ... on Country { name } ... on Region { name }
        ... on Malware { name } ... on ThreatActor { name } ... on Tool { name } ... on Vulnerability { name }
        ... on Incident { name } ... on Event { name } ... on Channel { name } ... on Narrative { name }
        ... on DataComponent { name } ... on DataSource { name } ... on Case { name }
        ... on StixCyberObservable { observable_value }
    }
`;

// Compact from/to resolution for relationship endpoints inside containers
const FROM_TO_FRAGMENT = `
    ... on BasicObject { id entity_type }
    ... on StixCyberObservable { observable_value }
    ... on AttackPattern { name } ... on Campaign { name } ... on CourseOfAction { name }
    ... on Individual { name } ... on Organization { name } ... on Sector { name } ... on System { name }
    ... on Indicator { name } ... on Infrastructure { name } ... on IntrusionSet { name }
    ... on Position { name } ... on City { name } ... on Country { name } ... on Region { name }
    ... on Malware { name } ... on ThreatActor { name } ... on Tool { name } ... on Vulnerability { name }
    ... on Incident { name } ... on Event { name } ... on Channel { name } ... on Narrative { name }
    ... on DataComponent { name } ... on DataSource { name } ... on Case { name }
`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const executeGraphQL = async (schema, context, query, variables = {}) => {
  const result = await graphql({ schema, source: query, variableValues: variables, contextValue: context });
  if (result.errors && result.errors.length > 0) {
    const msgs = result.errors.map((e) => e.message).join('; ');
    return { data: null, error: `GraphQL error: ${msgs}` };
  }
  return { data: result.data, error: null };
};

const textResult = (text) => ({ content: [{ type: 'text', text }] });

const edges = (data, key) => {
  if (!data) return [];
  const container = data[key];
  if (!container) return [];
  if (container.edges) return container.edges.filter((e) => e.node).map((e) => e.node);
  if (Array.isArray(container)) return container;
  return [];
};

const buildStixPattern = (observableType, value, hashAlgorithm = '') => {
  if (hashAlgorithm) {
    const prop = HASH_ALGORITHMS[hashAlgorithm.toUpperCase()];
    if (prop) return `[file:${prop} = '${value}']`;
    return null;
  }
  const entry = STIX_PATTERN_MAP[observableType];
  if (!entry) return null;
  if (entry.isInt) return `[${entry.scoType}:${entry.prop} = ${value}]`;
  return `[${entry.scoType}:${entry.prop} = '${value}']`;
};

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

export const registerAllTools = (server, schema, context) => {
  // ── 1. Search ──
  server.tool(
    'search_opencti',
    'Search for entities in OpenCTI by keyword. Returns STIX domain objects (threat actors, malware, indicators, reports, incidents, etc.) and STIX cyber observables (IPs, domains, URLs, hashes, etc.). Use types to filter by entity type.',
    {
      search: z.string().describe('Search keyword (e.g. APT29, ransomware, 192.168.1.1, CVE-2024-1234)'),
      types: z.array(z.string()).optional().describe('Filter by STIX entity types. Examples: Threat-Actor, Malware, Indicator, Report, Incident, Campaign, Vulnerability, Intrusion-Set, Tool, Attack-Pattern, Infrastructure, IPv4-Addr, Domain-Name, Url'),
      limit: z.number().int().optional().default(10).describe('Max results (default 10, max 50)'),
    },
    async ({ search, types, limit }) => {
      const query = `query SearchEntities($types: [String], $search: String, $first: Int, $orderBy: StixCoreObjectsOrdering, $orderMode: OrderingMode) {
        stixCoreObjects(types: $types, search: $search, first: $first, orderBy: $orderBy, orderMode: $orderMode) {
          edges { node { ${ENTITY_FIELDS} } }
          pageInfo { globalCount }
        }
      }`;
      const { data, error } = await executeGraphQL(schema, context, query, {
        search, types: types || null, first: Math.min(limit || 10, 50), orderBy: 'created_at', orderMode: 'desc',
      });
      if (error) return textResult(error);
      return textResult(JSON.stringify(data.stixCoreObjects));
    },
  );

  // ── 2. Get entity by ID ──
  server.tool(
    'get_opencti_entity',
    'Get full details of a specific entity by its OpenCTI ID or STIX ID. Returns comprehensive information including description, labels, markings, author, external references, and type-specific fields.',
    { entity_id: z.string().describe("The entity's OpenCTI internal ID or STIX ID (e.g. indicator--...)") },
    async ({ entity_id }) => {
      const query = `query GetEntity($id: String!) { stixCoreObject(id: $id) { ${ENTITY_FIELDS} } }`;
      const { data, error } = await executeGraphQL(schema, context, query, { id: entity_id });
      if (error) return textResult(error);
      if (!data.stixCoreObject) return textResult(`Entity '${entity_id}' not found.`);
      return textResult(JSON.stringify(data.stixCoreObject));
    },
  );

  // ── 3. Get relationship by ID ──
  server.tool(
    'get_opencti_relationship',
    'Get full details of a specific STIX core relationship by its OpenCTI ID or STIX ID. Returns the relationship type, source and target entities, description, confidence, time range, labels, markings, and author.',
    { relationship_id: z.string().describe("The relationship's OpenCTI internal ID or STIX ID (e.g. relationship--...)") },
    async ({ relationship_id }) => {
      const query = `query GetRelationship($id: String!) { stixCoreRelationship(id: $id) { ${RELATIONSHIP_FIELDS} } }`;
      const { data, error } = await executeGraphQL(schema, context, query, { id: relationship_id });
      if (error) return textResult(error);
      if (!data.stixCoreRelationship) return textResult(`Relationship '${relationship_id}' not found.`);
      return textResult(JSON.stringify(data.stixCoreRelationship));
    },
  );

  // ── 4. List STIX domain objects ──
  server.tool(
    'list_opencti_entities',
    'List STIX domain objects from OpenCTI with optional type filter, search, and ordering. Use this to browse threat actors, malware, indicators, reports, incidents, campaigns, vulnerabilities, etc.',
    {
      types: z.array(z.string()).optional().describe('Filter by entity types. Examples: Threat-Actor, Malware, Indicator, Report, Incident, Campaign, Vulnerability, Intrusion-Set, Tool, Attack-Pattern, Infrastructure, Note, Opinion, Course-Of-Action, Grouping, Observed-Data'),
      search: z.string().optional().default('').describe('Search keyword (optional)'),
      limit: z.number().int().optional().default(15).describe('Max results (default 15, max 50)'),
      order_by: z.string().optional().default('created_at').describe('Field to order by (default: created_at). Options: created_at, updated_at, created, modified, name, confidence'),
      order_mode: z.enum(['asc', 'desc']).optional().default('desc').describe('Sort order (default: desc)'),
      filters: z.string().optional().default('').describe('OpenCTI FilterGroup as JSON string (optional). Example: {"mode":"and","filters":[{"key":"confidence","values":["80"],"operator":"gte"}],"filterGroups":[]}'),
    },
    async ({ types, search, limit, order_by, order_mode, filters }) => {
      const query = `query ListSDOs($types: [String], $filters: FilterGroup, $search: String, $first: Int, $orderBy: StixDomainObjectsOrdering, $orderMode: OrderingMode) {
        stixDomainObjects(types: $types, filters: $filters, search: $search, first: $first, orderBy: $orderBy, orderMode: $orderMode) {
          edges { node { ${SDO_ENTITY_FIELDS} } }
          pageInfo { globalCount }
        }
      }`;
      const variables = {
        types: types || null, search: search || null, first: Math.min(limit || 15, 50),
        orderBy: order_by || 'created_at', orderMode: order_mode || 'desc',
      };
      if (filters) {
        try {
          variables.filters = JSON.parse(filters);
        } catch {
          return textResult("Error: 'filters' must be a valid JSON string (OpenCTI FilterGroup format).");
        }
      }
      const { data, error } = await executeGraphQL(schema, context, query, variables);
      if (error) return textResult(error);
      return textResult(JSON.stringify(data.stixDomainObjects));
    },
  );

  // ── 5. List STIX cyber observables ──
  server.tool(
    'list_opencti_observables',
    'List STIX cyber observables from OpenCTI with optional type filter and search. Use this to browse IP addresses, domains, URLs, files, email addresses, hashes, and other technical indicators.',
    {
      types: z.array(z.string()).optional().describe('Filter by observable types. Examples: IPv4-Addr, IPv6-Addr, Domain-Name, Url, Email-Addr, StixFile, Hostname, Mac-Addr, User-Agent, Artifact, Process, Software, Autonomous-System, X509-Certificate'),
      search: z.string().optional().default('').describe('Search keyword (optional)'),
      limit: z.number().int().optional().default(15).describe('Max results (default 15, max 50)'),
      order_by: z.string().optional().default('created_at').describe('Field to order by'),
      order_mode: z.enum(['asc', 'desc']).optional().default('desc').describe('Sort order'),
    },
    async ({ types, search, limit, order_by, order_mode }) => {
      const query = `query ListSCOs($types: [String], $search: String, $first: Int, $orderBy: StixCyberObservablesOrdering, $orderMode: OrderingMode) {
        stixCyberObservables(types: $types, search: $search, first: $first, orderBy: $orderBy, orderMode: $orderMode) {
          edges { node { ${SCO_ENTITY_FIELDS} } }
          pageInfo { globalCount }
        }
      }`;
      const { data, error } = await executeGraphQL(schema, context, query, {
        types: types || null, search: search || null, first: Math.min(limit || 15, 50),
        orderBy: order_by || 'created_at', orderMode: order_mode || 'desc',
      });
      if (error) return textResult(error);
      return textResult(JSON.stringify(data.stixCyberObservables));
    },
  );

  // ── 6. List STIX core relationships ──
  server.tool(
    'list_opencti_relationships',
    "List STIX core relationships of a specific entity. Shows what the entity is related to (e.g. 'indicates', 'uses', 'targets', 'attributed-to', 'related-to', 'mitigates', 'delivers', 'exploits'). Returns source and target entity names, relationship type, and confidence.",
    {
      entity_id: z.string().describe("The entity's OpenCTI ID"),
      relationship_type: z.string().optional().default('').describe('Filter by relationship type. Examples: indicates, uses, targets, attributed-to, related-to, mitigates, delivers, exploits, drops, communicates-with, based-on, variant-of, part-of, located-at'),
      from_types: z.array(z.string()).optional().describe('Filter source entity types (optional)'),
      to_types: z.array(z.string()).optional().describe('Filter target entity types (optional)'),
      limit: z.number().int().optional().default(20).describe('Max results (default 20)'),
    },
    async ({ entity_id, relationship_type, from_types, to_types, limit }) => {
      const query = `query ListRels($fromOrToId: [String], $relationship_type: [String], $fromTypes: [String], $toTypes: [String], $first: Int, $orderBy: StixCoreRelationshipsOrdering, $orderMode: OrderingMode) {
        stixCoreRelationships(fromOrToId: $fromOrToId, relationship_type: $relationship_type, fromTypes: $fromTypes, toTypes: $toTypes, first: $first, orderBy: $orderBy, orderMode: $orderMode) {
          edges { node { ${RELATIONSHIP_FIELDS} } }
          pageInfo { globalCount }
        }
      }`;
      const variables = {
        fromOrToId: [entity_id], first: Math.min(limit || 20, 50), orderBy: 'created_at', orderMode: 'desc',
      };
      if (relationship_type) variables.relationship_type = [relationship_type];
      if (from_types) variables.fromTypes = from_types;
      if (to_types) variables.toTypes = to_types;
      const { data, error } = await executeGraphQL(schema, context, query, variables);
      if (error) return textResult(error);
      return textResult(JSON.stringify(data.stixCoreRelationships));
    },
  );

  // ── 7. Create STIX core relationship ──
  server.tool(
    'create_opencti_relationship',
    "Create a STIX core relationship between two entities in OpenCTI. The relationship connects a source entity (from) to a target entity (to) with a specific relationship type (e.g. 'indicates', 'uses', 'targets').",
    {
      from_id: z.string().describe('Source entity OpenCTI ID'),
      to_id: z.string().describe('Target entity OpenCTI ID'),
      relationship_type: z.string().describe('Relationship type. Examples: indicates, uses, targets, attributed-to, related-to, mitigates, delivers, exploits, drops, communicates-with, based-on, variant-of, part-of'),
      description: z.string().optional().default('').describe('Relationship description (optional)'),
      confidence: z.number().int().optional().describe('Confidence level 0-100 (optional)'),
      start_time: z.string().optional().default('').describe('Start time ISO 8601 (optional)'),
      stop_time: z.string().optional().default('').describe('Stop time ISO 8601 (optional)'),
    },
    async ({ from_id, to_id, relationship_type, description, confidence, start_time, stop_time }) => {
      const query = `mutation CreateRelationship($input: StixCoreRelationshipAddInput!) {
        stixCoreRelationshipAdd(input: $input) {
          id standard_id entity_type relationship_type
          from { ... on BasicObject { id entity_type } ... on StixCyberObservable { observable_value } ${FROM_TO_FRAGMENT} }
          to { ... on BasicObject { id entity_type } ... on StixCyberObservable { observable_value } ${FROM_TO_FRAGMENT} }
        }
      }`;
      const input = { fromId: from_id, toId: to_id, relationship_type };
      if (description) input.description = description;
      if (confidence !== undefined) input.confidence = confidence;
      if (start_time) input.start_time = start_time;
      if (stop_time) input.stop_time = stop_time;
      const { data, error } = await executeGraphQL(schema, context, query, { input });
      if (error) return textResult(error);
      return textResult(JSON.stringify(data.stixCoreRelationshipAdd));
    },
  );

  // ── 8. Create STIX cyber observable ──
  server.tool(
    'create_opencti_observable',
    'Create a STIX cyber observable (IOC) in OpenCTI. Supports common observable types like IP addresses, domains, URLs, file hashes, etc. Optionally creates an associated indicator.',
    {
      type: z.string().describe(`Observable type. Supported: ${Object.keys(OBSERVABLE_TYPES).sort().join(', ')}`),
      value: z.string().describe('The observable value (e.g. IP address, domain name, URL, file name)'),
      x_opencti_score: z.number().int().optional().describe('Score 0-100 (optional)'),
      x_opencti_description: z.string().optional().default('').describe('Description (optional)'),
      create_indicator: z.boolean().optional().default(false).describe('Also create a STIX indicator for this observable (default: false)'),
    },
    async ({ type, value, x_opencti_score, x_opencti_description, create_indicator }) => {
      const typeInfo = OBSERVABLE_TYPES[type];
      if (!typeInfo) return textResult(`Unsupported observable type: '${type}'. Supported: ${Object.keys(OBSERVABLE_TYPES).sort().join(', ')}`);
      const { varName, inputType, fieldName } = typeInfo;
      const query = `mutation CreateObservable($type: String!, $x_opencti_score: Int, $x_opencti_description: String, $createIndicator: Boolean, $${varName}: ${inputType}) {
        stixCyberObservableAdd(type: $type, x_opencti_score: $x_opencti_score, x_opencti_description: $x_opencti_description, createIndicator: $createIndicator, ${varName}: $${varName}) {
          id entity_type observable_value x_opencti_score
        }
      }`;
      const variables = {
        type,
        [varName]: { [fieldName]: type === 'Autonomous-System' ? parseInt(value, 10) : value },
        createIndicator: create_indicator || false,
      };
      if (x_opencti_score !== undefined) variables.x_opencti_score = x_opencti_score;
      if (x_opencti_description) variables.x_opencti_description = x_opencti_description;
      const { data, error } = await executeGraphQL(schema, context, query, variables);
      if (error) return textResult(error);
      return textResult(JSON.stringify(data.stixCyberObservableAdd));
    },
  );

  // ── 9. Create note ──
  server.tool(
    'create_opencti_note',
    'Create an analyst note in OpenCTI attached to one or more entities. Use this to annotate findings, add context, or record analysis results. Markdown is supported in the content field.',
    {
      content: z.string().describe('Note content (Markdown supported)'),
      object_ids: z.array(z.string()).describe('List of entity IDs to attach the note to'),
      attribute_abstract: z.string().optional().default('').describe('Short abstract/summary (optional, auto-generated from content if omitted)'),
      note_types: z.array(z.string()).optional().describe('Note type(s): internal-note, external, assessment (default: internal-note)'),
      confidence: z.number().int().optional().describe('Confidence level 0-100 (optional)'),
    },
    async ({ content, object_ids, attribute_abstract, note_types, confidence }) => {
      const query = 'mutation CreateNote($input: NoteAddInput!) { noteAdd(input: $input) { id entity_type attribute_abstract } }';
      const input = { content, note_types: note_types || ['internal-note'], objects: object_ids };
      input.attribute_abstract = attribute_abstract || content.substring(0, 200);
      if (confidence !== undefined) input.confidence = confidence;
      const { data, error } = await executeGraphQL(schema, context, query, { input });
      if (error) return textResult(error);
      return textResult(JSON.stringify(data.noteAdd));
    },
  );

  // ── 10. Update SDO field(s) ──
  server.tool(
    'update_opencti_field',
    'Update a field on a STIX domain object in OpenCTI. Use this to change name, description, confidence, aliases, severity, and other fields. The value is always passed as a string or array of strings.',
    {
      entity_id: z.string().describe("The entity's OpenCTI ID"),
      key: z.string().describe('Field name to update. Examples: name, description, confidence, aliases, severity, x_opencti_score, revoked, first_seen, last_seen'),
      value: z.union([z.string(), z.array(z.string())]).describe('New value (string or array of strings)'),
    },
    async ({ entity_id, key, value }) => {
      const query = 'mutation UpdateSDO($id: ID!, $input: [EditInput]!) { stixDomainObjectEdit(id: $id) { fieldPatch(input: $input) { id entity_type } } }';
      const inputVal = Array.isArray(value) ? value : [value];
      const { data, error } = await executeGraphQL(schema, context, query, { id: entity_id, input: [{ key, value: inputVal }] });
      if (error) return textResult(error);
      const result = data.stixDomainObjectEdit?.fieldPatch || {};
      return textResult(JSON.stringify(result));
    },
  );

  // ── 11. Update relationship field(s) ──
  server.tool(
    'update_opencti_relationship_field',
    'Update a field on a STIX core relationship in OpenCTI. Use this to change description, confidence, start_time, stop_time, etc.',
    {
      relationship_id: z.string().describe("The relationship's OpenCTI ID"),
      key: z.string().describe('Field name. Examples: description, confidence, start_time, stop_time, revoked'),
      value: z.union([z.string(), z.array(z.string())]).describe('New value (string or array of strings)'),
    },
    async ({ relationship_id, key, value }) => {
      const query = 'mutation UpdateRel($id: ID!, $input: [EditInput]!) { stixCoreRelationshipEdit(id: $id) { fieldPatch(input: $input) { id entity_type } } }';
      const inputVal = Array.isArray(value) ? value : [value];
      const { data, error } = await executeGraphQL(schema, context, query, { id: relationship_id, input: [{ key, value: inputVal }] });
      if (error) return textResult(error);
      const result = data.stixCoreRelationshipEdit?.fieldPatch || {};
      return textResult(JSON.stringify(result));
    },
  );

  // ── 12. Delete entity ──
  server.tool(
    'delete_opencti_entity',
    'Delete any STIX core object (domain object or cyber observable) from OpenCTI by its ID. This is permanent and cannot be undone.',
    { entity_id: z.string().describe("The entity's OpenCTI ID to delete") },
    async ({ entity_id }) => {
      const query = 'mutation DeleteEntity($id: ID!) { stixCoreObjectEdit(id: $id) { delete } }';
      const { error } = await executeGraphQL(schema, context, query, { id: entity_id });
      if (error) return textResult(error);
      return textResult(`Entity ${entity_id} deleted.`);
    },
  );

  // ── 13. Delete relationship ──
  server.tool(
    'delete_opencti_relationship',
    'Delete a STIX core relationship from OpenCTI by its ID. This is permanent and cannot be undone.',
    { relationship_id: z.string().describe("The relationship's OpenCTI ID to delete") },
    async ({ relationship_id }) => {
      const query = 'mutation DeleteRelationship($id: ID!) { stixCoreRelationshipEdit(id: $id) { delete } }';
      const { error } = await executeGraphQL(schema, context, query, { id: relationship_id });
      if (error) return textResult(error);
      return textResult(`Relationship ${relationship_id} deleted.`);
    },
  );

  // ── 14. Add label to SDO ──
  server.tool(
    'add_opencti_label',
    "Add a label to a STIX domain object in OpenCTI and return the full updated entity. Creates the label automatically if it doesn't exist yet. Use labels for categorization (e.g. 'reviewed', 'high-priority', 'false-positive', 'apt').",
    {
      entity_id: z.string().describe("The entity's OpenCTI ID"),
      label_name: z.string().describe("Label name (e.g. 'reviewed', 'high-priority')"),
    },
    async ({ entity_id, label_name }) => {
      const findQ = 'query FindLabel($filters: FilterGroup) { labels(filters: $filters, first: 1) { edges { node { id value } } } }';
      const createQ = 'mutation CreateLabel($input: LabelAddInput!) { labelAdd(input: $input) { id value } }';
      const addQ = 'mutation AddLabel($id: ID!, $input: StixRefRelationshipAddInput!) { stixDomainObjectEdit(id: $id) { relationAdd(input: $input) { id } } }';
      const readQ = `query ReadEntity($id: String!) { stixCoreObject(id: $id) { ${ENTITY_FIELDS} } }`;

      const exactFilter = { mode: 'and', filters: [{ key: 'value', values: [label_name] }], filterGroups: [] };
      const { data: labelData, error: findErr } = await executeGraphQL(schema, context, findQ, { filters: exactFilter });
      if (findErr) return textResult(findErr);

      let labelId;
      const labelEdges = edges(labelData, 'labels');
      if (labelEdges.length > 0 && labelEdges[0].value === label_name) {
        labelId = labelEdges[0].id;
      } else {
        const { data: createData, error: createErr } = await executeGraphQL(schema, context, createQ, { input: { value: label_name } });
        if (createErr) return textResult(createErr);
        labelId = createData.labelAdd?.id;
        if (!labelId) return textResult(`Failed to create label '${label_name}'.`);
      }

      const { error: addErr } = await executeGraphQL(schema, context, addQ, { id: entity_id, input: { toId: labelId, relationship_type: 'object-label' } });
      if (addErr) return textResult(addErr);

      const { data: entityData, error: readErr } = await executeGraphQL(schema, context, readQ, { id: entity_id });
      if (readErr) return textResult(readErr);
      return textResult(JSON.stringify(entityData.stixCoreObject));
    },
  );

  // ── 15. Remove label from SDO ──
  server.tool(
    'remove_opencti_label',
    'Remove a label from a STIX domain object in OpenCTI.',
    {
      entity_id: z.string().describe("The entity's OpenCTI ID"),
      label_name: z.string().describe('Label name to remove'),
    },
    async ({ entity_id, label_name }) => {
      const findQ = 'query FindLabel($filters: FilterGroup) { labels(filters: $filters, first: 1) { edges { node { id value } } } }';
      const removeQ = 'mutation RemoveLabel($id: ID!, $toId: StixRef!, $relationship_type: String!) { stixDomainObjectEdit(id: $id) { relationDelete(toId: $toId, relationship_type: $relationship_type) { id } } }';

      const { data: labelData, error: findErr } = await executeGraphQL(schema, context, findQ, {
        filters: { mode: 'and', filters: [{ key: 'value', values: [label_name] }], filterGroups: [] },
      });
      if (findErr) return textResult(findErr);
      const labelEdges = edges(labelData, 'labels');
      if (labelEdges.length === 0) return textResult(`Label '${label_name}' not found.`);

      const { error: removeErr } = await executeGraphQL(schema, context, removeQ, {
        id: entity_id, toId: labelEdges[0].id, relationship_type: 'object-label',
      });
      if (removeErr) return textResult(removeErr);
      return textResult(`Label '${label_name}' removed from entity ${entity_id}.`);
    },
  );

  // ── 16. Add marking definition to SDO ──
  server.tool(
    'add_opencti_marking',
    "Add a marking definition (TLP, PAP, etc.) to a STIX domain object in OpenCTI. You need the marking definition's OpenCTI ID (get it from the entity's current markings or by searching for marking definitions).",
    {
      entity_id: z.string().describe("The entity's OpenCTI ID"),
      marking_definition_id: z.string().describe("The marking definition's OpenCTI ID"),
    },
    async ({ entity_id, marking_definition_id }) => {
      const query = 'mutation AddMarking($id: ID!, $input: StixRefRelationshipAddInput!) { stixDomainObjectEdit(id: $id) { relationAdd(input: $input) { id } } }';
      const { error } = await executeGraphQL(schema, context, query, {
        id: entity_id, input: { toId: marking_definition_id, relationship_type: 'object-marking' },
      });
      if (error) return textResult(error);
      return textResult(`Marking definition ${marking_definition_id} added to entity ${entity_id}.`);
    },
  );

  // ── 17. Remove marking definition from SDO ──
  server.tool(
    'remove_opencti_marking',
    'Remove a marking definition from a STIX domain object in OpenCTI.',
    {
      entity_id: z.string().describe("The entity's OpenCTI ID"),
      marking_definition_id: z.string().describe("The marking definition's OpenCTI ID"),
    },
    async ({ entity_id, marking_definition_id }) => {
      const query = 'mutation RemoveMarking($id: ID!, $toId: StixRef!, $relationship_type: String!) { stixDomainObjectEdit(id: $id) { relationDelete(toId: $toId, relationship_type: $relationship_type) { id } } }';
      const { error } = await executeGraphQL(schema, context, query, {
        id: entity_id, toId: marking_definition_id, relationship_type: 'object-marking',
      });
      if (error) return textResult(error);
      return textResult(`Marking definition ${marking_definition_id} removed from entity ${entity_id}.`);
    },
  );

  // ── 18. Get container with all objects ──
  server.tool(
    'get_opencti_container_full',
    'Get the full contents of an OpenCTI container (Report, Grouping, Note, Observed-Data, Opinion, Case-Incident, Case-Rfi, Case-Rft, Feedback) with all contained entities and relationships resolved.',
    {
      container_id: z.string().describe('The OpenCTI ID or STIX ID of the container (Report, Grouping, Note, Case, etc.)'),
      limit: z.number().int().optional().default(200).describe('Max objects to return (default 200, max 1000). Start with small limits and increase only if needed.'),
    },
    async ({ container_id, limit }) => {
      const nd = `
        ... on BasicObject { id entity_type } ... on BasicRelationship { id entity_type }
        ... on AttackPattern { name description } ... on Campaign { name description }
        ... on CourseOfAction { name description } ... on Incident { name description }
        ... on Indicator { name description } ... on Infrastructure { name description }
        ... on IntrusionSet { name description } ... on Malware { name description }
        ... on ThreatActor { name description } ... on Tool { name description }
        ... on Vulnerability { name description } ... on Report { name description }
        ... on Note { attribute_abstract content } ... on ObservedData { first_observed last_observed }
        ... on Opinion { explanation opinion } ... on Grouping { name description }
        ... on Individual { name description } ... on Organization { name description }
        ... on Sector { name description } ... on System { name description }
        ... on City { name description } ... on Country { name description }
        ... on Region { name description } ... on Position { name description }
        ... on Event { name description } ... on Channel { name description }
        ... on Narrative { name description } ... on DataComponent { name description }
        ... on DataSource { name description } ... on Case { name description }
        ... on StixCyberObservable { observable_value x_opencti_description }
        ... on IPv4Addr { value } ... on IPv6Addr { value } ... on DomainName { value }
        ... on Url { value } ... on EmailAddr { value } ... on Hostname { value }
        ... on StixFile { sco_name: name } ... on Software { sco_name: name } ... on Mutex { sco_name: name }
        ... on StixCoreRelationship { relationship_type description from { ${FROM_TO_FRAGMENT} } to { ${FROM_TO_FRAGMENT} } }
      `;
      const oc = `objects(first: $first) { edges { node { ${nd} } } pageInfo { globalCount } }`;
      const query = `query ContainerFull($id: String!, $first: Int) {
        stixDomainObject(id: $id) {
          id entity_type standard_id created_at
          ... on Report { name description report_types published ${oc} }
          ... on Grouping { name description context ${oc} }
          ... on Note { attribute_abstract content note_types ${oc} }
          ... on ObservedData { first_observed last_observed number_observed ${oc} }
          ... on Opinion { explanation opinion ${oc} }
          ... on CaseIncident { name description ${oc} }
          ... on CaseRfi { name description ${oc} }
          ... on CaseRft { name description ${oc} }
          ... on Feedback { name description ${oc} }
        }
      }`;
      const first = Math.min(Math.max(limit || 200, 1), 1000);
      const { data, error } = await executeGraphQL(schema, context, query, { id: container_id, first });
      if (error) return textResult(error);
      if (!data.stixDomainObject) return textResult(`Container ${container_id} not found.`);
      return textResult(JSON.stringify(data.stixDomainObject));
    },
  );

  // ── 19. Create STIX indicator ──
  server.tool(
    'create_opencti_indicator',
    'Create a STIX indicator in OpenCTI. You can either provide a raw STIX pattern string, or provide an observable_type + observable_value to auto-generate the pattern. For file hash indicators, also specify hash_algorithm (MD5, SHA-1, SHA-256). Optionally set create_observables=true to also create the corresponding observable(s).',
    {
      name: z.string().optional().default('').describe('Indicator name (defaults to the STIX pattern if omitted)'),
      pattern: z.string().optional().default('').describe("Raw STIX 2.1 pattern (e.g. \"[ipv4-addr:value = '1.2.3.4']\" or \"[file:hashes.'SHA-256' = 'abc...']\"). If omitted, provide observable_type + observable_value for auto-generation."),
      observable_type: z.string().optional().default('').describe(`Observable type for auto-pattern generation. Supported: ${Object.keys(STIX_PATTERN_MAP).sort().join(', ')}`),
      observable_value: z.string().optional().default('').describe('Observable value for auto-pattern generation (e.g. IP, domain, hash, URL)'),
      hash_algorithm: z.string().optional().default('').describe('Hash algorithm when creating file hash indicators: MD5, SHA-1, SHA-256, SHA-512, SSDEEP'),
      description: z.string().optional().default('').describe('Indicator description'),
      confidence: z.number().int().optional().describe('Confidence level 0-100'),
      x_opencti_score: z.number().int().optional().describe('OpenCTI score 0-100'),
      indicator_types: z.array(z.string()).optional().describe('Indicator types: malicious-activity, anomalous-activity, benign, compromised, unknown'),
      valid_from: z.string().optional().default('').describe('Valid from date (ISO 8601)'),
      valid_until: z.string().optional().default('').describe('Valid until date (ISO 8601)'),
      create_observables: z.boolean().optional().default(false).describe('Also create corresponding STIX observable(s) from the pattern (default: false)'),
    },
    async ({
      name, pattern, observable_type, observable_value, hash_algorithm,
      description, confidence, x_opencti_score, indicator_types,
      valid_from, valid_until, create_observables,
    }) => {
      let finalPattern = pattern;
      if (!finalPattern) {
        if (!observable_type || !observable_value) {
          return textResult("Error: provide either 'pattern' (raw STIX pattern) or both 'observable_type' and 'observable_value' for auto-generation.");
        }
        finalPattern = buildStixPattern(observable_type, observable_value, hash_algorithm);
        if (!finalPattern) {
          if (hash_algorithm) return textResult(`Error: unrecognized hash algorithm '${hash_algorithm}'.`);
          return textResult(`Error: cannot auto-generate pattern for type '${observable_type}'. Supported: ${Object.keys(STIX_PATTERN_MAP).sort().join(', ')}`);
        }
      }
      let mainObsType = observable_type || '';
      if (hash_algorithm && !observable_type) mainObsType = 'StixFile';
      if (!mainObsType) {
        const inferMap = {
          'ipv4-addr:': 'IPv4-Addr', 'ipv6-addr:': 'IPv6-Addr', 'domain-name:': 'Domain-Name',
          'url:': 'Url', 'email-addr:': 'Email-Addr', 'mac-addr:': 'Mac-Addr', 'file:': 'StixFile',
          'hostname:': 'Hostname', 'autonomous-system:': 'Autonomous-System', 'directory:': 'Directory',
          'mutex:': 'Mutex', 'software:': 'Software', 'user-agent:': 'User-Agent',
        };
        mainObsType = Object.entries(inferMap).find(([token]) => finalPattern.includes(token))?.[1] || 'Unknown';
      }
      const query = `mutation CreateIndicator($input: IndicatorAddInput!) {
        indicatorAdd(input: $input) { id entity_type standard_id name pattern pattern_type valid_from valid_until x_opencti_score x_opencti_main_observable_type }
      }`;
      const input = { name: name || finalPattern, pattern: finalPattern, pattern_type: 'stix', x_opencti_main_observable_type: mainObsType };
      if (description) input.description = description;
      if (confidence !== undefined) input.confidence = confidence;
      if (x_opencti_score !== undefined) input.x_opencti_score = x_opencti_score;
      if (indicator_types) input.indicator_types = indicator_types;
      if (valid_from) input.valid_from = valid_from;
      if (valid_until) input.valid_until = valid_until;
      if (create_observables) input.x_create_opencti_observables = true;
      const { data, error } = await executeGraphQL(schema, context, query, { input });
      if (error) return textResult(error);
      return textResult(JSON.stringify(data.indicatorAdd));
    },
  );

  // ── 20. Create container ──
  server.tool(
    'create_opencti_container',
    'Create a container in OpenCTI: Report, Case-Incident, Case-Rfi (Request for Information), Case-Rft (Request for Takedown), or Grouping. Containers hold references to other STIX objects. Optionally pass object_ids to add entities/relationships at creation.',
    {
      container_type: z.enum(Object.keys(CONTAINER_MUTATIONS).sort()).describe('Container type to create'),
      name: z.string().describe('Container name'),
      description: z.string().optional().default('').describe('Description (Markdown supported)'),
      content: z.string().optional().default('').describe('Rich content body (Markdown, optional)'),
      published: z.string().optional().default('').describe('Publication date (ISO 8601). Required for Report.'),
      context: z.string().optional().default('').describe('Grouping context. Required for Grouping. Examples: suspicious-activity, malware-analysis, unspecified'),
      report_types: z.array(z.string()).optional().describe('Report types (for Report only): threat-report, internal-report, attack-pattern, tool, etc.'),
      severity: z.string().optional().default('').describe('Severity (for Case types): low, medium, high, critical'),
      priority: z.string().optional().default('').describe('Priority (for Case types): P1, P2, P3, P4'),
      confidence: z.number().int().optional().describe('Confidence level 0-100'),
      object_ids: z.array(z.string()).optional().describe('List of entity/relationship IDs to include in the container at creation'),
    },
    async ({ container_type, name, description, content, published, context: ctx, report_types, severity, priority, confidence, object_ids }) => {
      const mutInfo = CONTAINER_MUTATIONS[container_type];
      if (!mutInfo) return textResult(`Unsupported container type: '${container_type}'. Supported: ${Object.keys(CONTAINER_MUTATIONS).sort().join(', ')}`);
      if (container_type === 'Report' && !published) return textResult("Error: 'published' date is required for Report (ISO 8601 format).");
      if (container_type === 'Grouping' && !ctx) return textResult("Error: 'context' is required for Grouping.");

      const containerFragments = {
        Report: 'name description published report_types',
        'Case-Incident': 'name description severity priority',
        'Case-Rfi': 'name description severity priority',
        'Case-Rft': 'name description severity priority',
        Grouping: 'name description context',
      };
      const fields = containerFragments[container_type] || 'name description';
      const query = `mutation CreateContainer($input: ${mutInfo.inputType}!) { ${mutInfo.mutationName}(input: $input) { id entity_type standard_id ${fields} } }`;
      const input = { name };
      if (description) input.description = description;
      if (content) input.content = content;
      if (confidence !== undefined) input.confidence = confidence;
      if (object_ids) input.objects = object_ids;
      if (container_type === 'Report') {
        input.published = published;
        if (report_types) input.report_types = report_types;
      }
      if (container_type === 'Grouping') input.context = ctx;
      if (container_type.startsWith('Case-')) {
        if (severity) input.severity = severity;
        if (priority) input.priority = priority;
      }
      const { data, error } = await executeGraphQL(schema, context, query, { input });
      if (error) return textResult(error);
      return textResult(JSON.stringify(data[mutInfo.mutationName]));
    },
  );

  // ── 21. Create STIX domain object ──
  server.tool(
    'create_opencti_entity',
    `Create a STIX domain object (entity) in OpenCTI. Supports: ${Object.keys(SDO_MUTATIONS).sort().join(', ')}. Use this for threat actors, malware, campaigns, incidents, vulnerabilities, attack patterns, tools, intrusion sets, etc.`,
    {
      type: z.enum(Object.keys(SDO_MUTATIONS).sort()).describe('STIX domain object type to create'),
      name: z.string().describe('Entity name'),
      description: z.string().optional().default('').describe('Description (Markdown supported)'),
      aliases: z.array(z.string()).optional().describe('Alternative names / aliases (for types that support them)'),
      confidence: z.number().int().optional().describe('Confidence level 0-100'),
      first_seen: z.string().optional().default('').describe('First seen date (ISO 8601, for Campaign, Incident, Malware, etc.)'),
      last_seen: z.string().optional().default('').describe('Last seen date (ISO 8601)'),
      severity: z.string().optional().default('').describe('Severity (for Incident): low, medium, high, critical'),
      objective: z.string().optional().default('').describe('Objective (for Campaign)'),
      malware_types: z.array(z.string()).optional().describe('Malware types (for Malware): backdoor, ransomware, trojan, worm, dropper, etc.'),
      is_family: z.boolean().optional().describe('Whether this is a malware family (for Malware)'),
      threat_actor_types: z.array(z.string()).optional().describe('Threat actor types (for Threat-Actor-*): nation-state, criminal, hacktivist, insider, etc.'),
      tool_types: z.array(z.string()).optional().describe('Tool types (for Tool): exploitation, remote-access, information-gathering, etc.'),
      infrastructure_types: z.array(z.string()).optional().describe('Infrastructure types (for Infrastructure): botnet, command-and-control, hosting-malware, etc.'),
    },
    async ({
      type, name, description, aliases, confidence, first_seen, last_seen,
      severity, objective, malware_types, is_family,
      threat_actor_types, tool_types, infrastructure_types,
    }) => {
      const mutInfo = SDO_MUTATIONS[type];
      if (!mutInfo) return textResult(`Unsupported entity type: '${type}'. Supported: ${Object.keys(SDO_MUTATIONS).sort().join(', ')}`);
      const query = `mutation CreateSDO($input: ${mutInfo.inputType}!) {
        ${mutInfo.mutationName}(input: $input) {
          id entity_type standard_id
          ... on AttackPattern { name description } ... on Campaign { name description }
          ... on Channel { name description } ... on CourseOfAction { name description }
          ... on Event { name description } ... on Incident { name description severity }
          ... on Individual { name description } ... on Infrastructure { name description }
          ... on IntrusionSet { name description } ... on Malware { name description is_family }
          ... on Narrative { name description } ... on Organization { name description }
          ... on Sector { name description } ... on ThreatActor { name description }
          ... on Tool { name description } ... on Vulnerability { name description }
        }
      }`;
      const input = { name };
      if (description) input.description = description;
      if (confidence !== undefined) input.confidence = confidence;
      if (aliases) input.aliases = aliases;
      if (first_seen) input.first_seen = first_seen;
      if (last_seen) input.last_seen = last_seen;
      if (severity) input.severity = severity;
      if (objective) input.objective = objective;
      if (malware_types && type === 'Malware') input.malware_types = malware_types;
      if (is_family !== undefined && type === 'Malware') input.is_family = is_family;
      if (threat_actor_types && type.startsWith('Threat-Actor')) input.threat_actor_types = threat_actor_types;
      if (tool_types && type === 'Tool') input.tool_types = tool_types;
      if (infrastructure_types && type === 'Infrastructure') input.infrastructure_types = infrastructure_types;
      const { data, error } = await executeGraphQL(schema, context, query, { input });
      if (error) return textResult(error);
      return textResult(JSON.stringify(data[mutInfo.mutationName]));
    },
  );

  // ── 22. Add entity/relationship to container ──
  server.tool(
    'add_opencti_to_container',
    'Add one or more entities or relationships to an OpenCTI container (Report, Case, Grouping, Note, etc.). Pass the container ID and a list of entity/relationship IDs to add.',
    {
      container_id: z.string().describe("The container's OpenCTI ID"),
      entity_ids: z.array(z.string()).describe('List of entity or relationship IDs to add to the container'),
    },
    async ({ container_id, entity_ids }) => {
      const query = 'mutation AddToContainer($id: ID!, $input: StixRefRelationshipAddInput!) { stixDomainObjectEdit(id: $id) { relationAdd(input: $input) { id } } }';
      const added = [];
      const errors = [];
      for (const eid of entity_ids) {
        const { error } = await executeGraphQL(schema, context, query, { id: container_id, input: { toId: eid, relationship_type: 'object' } });
        if (error) errors.push(`${eid}: ${error}`);
        else added.push(eid);
      }
      const parts = [];
      if (added.length > 0) parts.push(`Added ${added.length} object(s) to container ${container_id}: ${added.join(', ')}`);
      if (errors.length > 0) parts.push(`Errors: ${errors.join('; ')}`);
      return textResult(parts.length > 0 ? parts.join('\n') : 'No objects were added.');
    },
  );

  // ── 23. Remove entity/relationship from container ──
  server.tool(
    'remove_opencti_from_container',
    'Remove one or more entities or relationships from an OpenCTI container (Report, Case, Grouping, Note, etc.). Pass the container ID and a list of entity/relationship IDs to remove.',
    {
      container_id: z.string().describe("The container's OpenCTI ID"),
      entity_ids: z.array(z.string()).describe('List of entity or relationship IDs to remove from the container'),
    },
    async ({ container_id, entity_ids }) => {
      const query = 'mutation RemoveFromContainer($id: ID!, $toId: StixRef!, $relationship_type: String!) { stixDomainObjectEdit(id: $id) { relationDelete(toId: $toId, relationship_type: $relationship_type) { id } } }';
      const removed = [];
      const errors = [];
      for (const eid of entity_ids) {
        const { error } = await executeGraphQL(schema, context, query, { id: container_id, toId: eid, relationship_type: 'object' });
        if (error) errors.push(`${eid}: ${error}`);
        else removed.push(eid);
      }
      const parts = [];
      if (removed.length > 0) parts.push(`Removed ${removed.length} object(s) from container ${container_id}: ${removed.join(', ')}`);
      if (errors.length > 0) parts.push(`Errors: ${errors.join('; ')}`);
      return textResult(parts.length > 0 ? parts.join('\n') : 'No objects were removed.');
    },
  );

  // ── 24. Promote observable to indicator ──
  server.tool(
    'promote_opencti_observable',
    "Promote an existing STIX Cyber Observable to a STIX Indicator. Reads the observable, auto-generates the STIX pattern, creates the indicator, and links them with a 'based-on' relationship. Works with IPs, domains, URLs, emails, file hashes, hostnames, and other common observable types.",
    {
      entity_id: z.string().describe("The observable's OpenCTI ID to promote"),
      x_opencti_score: z.number().int().optional().describe('Score to assign to the new indicator (0-100)'),
      indicator_types: z.array(z.string()).optional().describe('Indicator types: malicious-activity, anomalous-activity, benign, compromised, unknown'),
    },
    async ({ entity_id, x_opencti_score, indicator_types }) => {
      const readQ = `query ReadObs($id: String!) { stixCoreObject(id: $id) { ${ENTITY_FIELDS} } }`;
      const { data: readData, error: readErr } = await executeGraphQL(schema, context, readQ, { id: entity_id });
      if (readErr) return textResult(readErr);
      const entity = readData.stixCoreObject;
      if (!entity) return textResult(`Entity '${entity_id}' not found.`);

      const entityType = entity.entity_type || '';
      const parents = entity.parent_types || [];
      if (!parents.includes('Stix-Cyber-Observable') && !parents.includes('StixCyberObservable')) {
        return textResult(`Entity '${entity_id}' is a ${entityType}, not an observable. This tool only works with STIX Cyber Observables.`);
      }

      let obsValue = entity.observable_value || entity.value || entity.sco_name || entity.name;
      if (!obsValue) return textResult(`Could not determine the value of observable '${entity_id}'.`);

      let hashAlg = '';
      if (entityType === 'StixFile' || entityType === 'Artifact') {
        const hashes = entity.hashes || [];
        for (const pref of ['SHA-256', 'SHA-1', 'MD5']) {
          const found = hashes.find((h) => h && h.algorithm === pref);
          if (found) {
            hashAlg = pref;
            obsValue = found.hash;
            break;
          }
        }
      }

      const stixPattern = buildStixPattern(entityType, obsValue, hashAlg);
      if (!stixPattern) return textResult(`Cannot auto-generate STIX pattern for ${entityType} '${obsValue}'. Use create_opencti_indicator with a manual pattern.`);

      const createQ = 'mutation CreateIndicator($input: IndicatorAddInput!) { indicatorAdd(input: $input) { id entity_type standard_id name pattern pattern_type x_opencti_main_observable_type x_opencti_score } }';
      const indInput = { name: `Indicator: ${obsValue}`, pattern: stixPattern, pattern_type: 'stix', x_opencti_main_observable_type: entityType };
      if (x_opencti_score !== undefined) indInput.x_opencti_score = x_opencti_score;
      if (indicator_types) indInput.indicator_types = indicator_types;
      const { data: indData, error: indErr } = await executeGraphQL(schema, context, createQ, { input: indInput });
      if (indErr) return textResult(indErr);
      const ind = indData.indicatorAdd || {};

      const relQ = 'mutation CreateBasedOn($input: StixCoreRelationshipAddInput!) { stixCoreRelationshipAdd(input: $input) { id } }';
      const { error: relErr } = await executeGraphQL(schema, context, relQ, { input: { fromId: ind.id, toId: entity_id, relationship_type: 'based-on' } });
      if (relErr) return textResult(relErr);

      return textResult(JSON.stringify({ observable: { entity_type: entityType, value: obsValue, id: entity_id }, indicator: ind, pattern: stixPattern, relationship: 'based-on' }));
    },
  );

  // ── 25. Upload file to entity ──
  server.tool(
    'upload_opencti_file',
    'Upload or attach a file to an existing OpenCTI entity. Supports any entity type (reports, incidents, indicators, observables, etc.). Provide the file content as text (UTF-8) or base64-encoded binary.',
    {
      entity_id: z.string().describe('The OpenCTI entity ID to attach the file to'),
      file_name: z.string().describe("File name with extension (e.g. 'report.pdf', 'iocs.csv', 'analysis.md')"),
      file_content: z.string().describe("File content — plain text (UTF-8) by default, or base64-encoded if encoding is set to 'base64'"),
      encoding: z.enum(['text', 'base64']).optional().default('text').describe("Content encoding: 'text' for UTF-8 text content (default), 'base64' for binary files"),
      mime_type: z.string().optional().default('application/octet-stream').describe("MIME type (e.g. 'text/csv', 'application/pdf'). Default: 'application/octet-stream'"),
      no_trigger_import: z.boolean().optional().default(true).describe('Skip triggering import connectors for this file (default: true)'),
    },
    async ({ entity_id, file_name, _file_content, _encoding, _mime_type, _no_trigger_import }) => {
      // File upload requires multipart GraphQL which cannot be done via internal graphql() execution.
      // Return a helpful message indicating this limitation.
      return textResult(
        'File upload via MCP is not supported in the embedded server because it requires multipart form data. '
        + `Use the OpenCTI REST API or UI to upload files. Entity ID: ${entity_id}, File: ${file_name}`,
      );
    },
  );

  // ── 26. Import dashboard ──
  server.tool(
    'import_opencti_dashboard',
    "Import a custom dashboard into OpenCTI from a JSON configuration. Provide the exact JSON object as exported from OpenCTI. The 'configuration.manifest' field must be a base64-encoded string (standard OpenCTI export format). Returns the new workspace/dashboard ID.",
    {
      dashboard_json: z.string().describe("The dashboard configuration as a JSON string. Required top-level fields: 'type' (must be 'dashboard'), 'openCTI_version', and 'configuration' object with 'name' and 'manifest' (base64-encoded JSON)."),
      raw_widgets: z.boolean().optional().default(false).describe('When true, dashboard_json contains raw widget configurations that will be auto-encoded.'),
    },
    async ({ _dashboard_json, _raw_widgets }) => {
      // Dashboard import requires multipart file upload which cannot be done via internal graphql() execution.
      // Return a helpful message indicating this limitation.
      return textResult(
        'Dashboard import via MCP is not supported in the embedded server because it requires multipart file upload. '
        + 'Use the OpenCTI REST API or UI to import dashboards.',
      );
    },
  );
};
