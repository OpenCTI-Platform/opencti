import gql from 'graphql-tag' ;

// contains common type definitions used across OSCAL objects
const typeDefs = gql`

  "Defines identifying information about Base64 Content"
  type Base64Content {
    "Identifies the name of the file before it was encoded as Base64 to be embedded in a resource. This is the name that will be assigned to the file when the file is decoded."
    filename: String
    "Identifies the media type as defined by the Internet Assigned Numbers Authority (IANA)."
    media_type: String
    "Identifies the content that is base64 encoded."
    value: String
  }

  input Base64ContentAddInput {
    filename: String
    media_type: String
    value: String
  }

  "Defines identifying information about a citation."
  type Citation {
    "Identifies a line of citation text."
    text: String!
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
  }

  input CitationAddInput {
    "Identifies a line of citation text."
    text: String!
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReferenceAddInput]
  }

  "Defines identifying information about an OSCAL Model."
  interface Model {
    # Basic Object
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    # ExternalObject
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
    # Metadata
    "Identifies the name given to the document."
    name: String!
    "Identifies the date and time the document was published."
    published: DateTime
    "Identifies the date and time the document as last modified."
    last_modified: DateTime!
    "Identifies the current version of the document."
    version: String!
    "Identifies the OSCAL model version the document was authored against."
    oscal_version: String!
    "Identifies a list of revisions to the containing document."
    revisions: [Revision]
    "Identifies references to previous versions of this document."
    document_ids: [OscalObject]
    "Identifies one or more references to a function assumed or expected to be assumed by a party in a specific situation."
    roles: [OscalRole]
    "Identifies one or more references to a location."
    locations: [OscalLocation]
    "Identifies one or more references to a responsible entity which is either a person or an organization."
    parties: [OscalParty]
    "Identifies one or more references to a set of organizations or persons that have responsibility for performing a referenced role in the context of the containing object."
    responsible_parties: [ResponsibleParty]
    # Back-matter
    resources: [OscalResource]
  }

  "Defines the identifying information about an OSCAL object."
  interface OscalObject {
    # Basic Object
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    # ExternalObject
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
  }

  "Defines identifying information about a location."
  type OscalLocation implements OscalObject & Location {
    # OscalObject
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
    # Location
    "Identifies the name given to the location."
    name: String!
    "Identifies a brief description of the location."
    description: String
    # OscalLocation
    "Identifies the type of the location."
    location_type: LocationType
    "Identifies the purpose of the location."
    location_class: LocationClass
    "Identifies a postal addresses for the location."
    address: CivicAddress
    "Identifies one or more email addresses for the location."
    email_addresses: EmailAddress
    "Identifies one or more telephone numbers used to contact the the location."
    telephone_numbers: [TelephoneNumber]
    "Identifies one or more uniform resource locator (URL) for a web site or Internet presence associated with the location."
    urls: [URL]
  }

  input OscalLocationAddInput {
      # Basic Object
      id: String!
      object_type: String!
      # ExternalObject
      created: DateTime!
      modified: DateTime!
      labels: [String]
      external_references: [ExternalReferenceAddInput]
      notes: [NoteAddInput]
      # Location
      name: String!
      description: String
      # OscalLocation
      location_type: LocationType
      location_class: LocationClass
      address: [CivicAddressAddInput]
      email_addresses: EmailAddress
      telephone_numbers: [TelephoneNumberAddInput]
      urls: [URL]
  }

  type OscalOrganization implements OscalObject & Identity & OscalParty {
      # OscalObject
      "Uniquely identifies this object."
      id: String!
      "Identifies the type of the Object."
      object_type: String!
      "Indicates the date and time at which the object was originally created."
      created: DateTime!
      "Indicates the date and time that this particular version of the object was last modified.""
      modified: DateTime!
      "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
      labels: [String]
      "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
      external_references: [ExternalReference]
      "Identifies one or more references to additional commentary on the Model."
      notes: [Note]
      # Identity
      "Identifies the name given to the party."
      name: String!
      "Identifies a brief description of the Party."
      description: String
      # OscalParty
      "Identifies the kind of party the object describes."
      party_type: PartyType!
      "Identifies a short common name, abbreviation, or acronym for the party."
      short_name: String
      "Identifies one or more external identifiers for a person or organization using a designated scheme. e.g. an Open Researcher and Contributor ID (ORCID)."
      external_ids: [ExternalReference]
      "Identifies a postal addresses for the location."
      address: CivicAddress
      "Identifies one or more email addresses for the location."
      email_addresses: EmailAddress
      "Identifies one or more telephone numbers used to contact the the location."
      telephone_numbers: [TelephoneNumber]
      "Identifies one or more references to a location."
      locations: [OscalLocation]
      "Identifies that the party object is a member of the organization."
      member_of_organizations: [OscalOrganization]
      "Identifies a mail stop associated with the party."
      mail_stop: String
      "Identifies the name or number of the party's office."
      office: String
  }

  input OscalOrganizationAddInput {
      # OscalObject
      "Uniquely identifies this object."
      id: String!
      "Identifies the type of the Object."
      object_type: String!
      "Indicates the date and time at which the object was originally created."
      created: DateTime!
      "Indicates the date and time that this particular version of the object was last modified.""
      modified: DateTime!
      "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
      labels: [String]
      "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
      external_references: [ExternalReferenceAddInput]
      "Identifies one or more references to additional commentary on the Model."
      notes: [NoteAddInput]
      # Identity
      "Identifies the name given to the party."
      name: String!
      "Identifies a brief description of the Party."
      description: String
      # OscalParty
      "Identifies the kind of party the object describes."
      party_type: PartyType!
      "Identifies a short common name, abbreviation, or acronym for the party."
      short_name: String
      "Identifies one or more external identifiers for a person or organization using a designated scheme. e.g. an Open Researcher and Contributor ID (ORCID)."
      external_ids: [ExternalReferenceAddInput]
      "Identifies a postal addresses for the location."
      address: CivicAddress
      "Identifies one or more email addresses for the location."
      email_addresses: EmailAddress
      "Identifies one or more telephone numbers used to contact the the location."
      telephone_numbers: [TelephoneNumberAddInput]
      "Identifies one or more references to a location."
      locations: [OscalLocation]
      "Identifies that the party object is a member of the organization."
      member_of_organizations: [OscalOrganizationAddInput]
      "Identifies a mail stop associated with the party."
      mail_stop: String
      "Identifies the name or number of the party's office."
      office: String
  }

  interface OscalParty {
    # OscalObject
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
    # Identity
    "Identifies the name given to the party."
    name: String!
    "Identifies a brief description of the Party."
    description: String
    # OscalParty
    "Identifies the kind of party the object describes."
    party_type: PartyType!
    "Identifies a short common name, abbreviation, or acronym for the party."
    short_name: String
    "Identifies one or more external identifiers for a person or organization using a designated scheme. e.g. an Open Researcher and Contributor ID (ORCID)."
    external_ids: [ExternalReference]
    "Identifies a postal addresses for the location."
    address: CivicAddress
    "Identifies one or more email addresses for the location."
    email_addresses: EmailAddress
    "Identifies one or more telephone numbers used to contact the the location."
    telephone_numbers: [TelephoneNumber]
    "Identifies one or more references to a location."
    locations: [OscalLocation]
    "Identifies that the party object is a member of the organization."
    member_of_organizations: [OscalOrganization]
    "Identifies a mail stop associated with the party."
    mail_stop: String
    "Identifies the  name or number of the party's office."
    office: String
  }

  input OscalPartyAddInput {
    # OscalObject
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReferenceAddInput]
    "Identifies one or more references to additional commentary on the Model."
    notes: [NoteAddInput]
    # Identity
    "Identifies the name given to the party."
    name: String!
    "Identifies a brief description of the Party."
    description: String
    # OscalParty
    "Identifies the kind of party the object describes."
    party_type: PartyType!
    "Identifies a short common name, abbreviation, or acronym for the party."
    short_name: String
    "Identifies one or more external identifiers for a person or organization using a designated scheme. e.g. an Open Researcher and Contributor ID (ORCID)."
    external_ids: [ExternalReferenceAddInput]
    "Identifies a postal addresses for the location."
    address: CivicAddress
    "Identifies one or more email addresses for the location."
    email_addresses: EmailAddress
    "Identifies one or more telephone numbers used to contact the the location."
    telephone_numbers: [TelephoneNumberAddInput]
    "Identifies one or more references to a location."
    locations: [OscalLocationAddInput]
    "Identifies that the party object is a member of the organization."
    member_of_organizations: [OscalOrganizationAddInput]
    "Identifies a mail stop associated with the party."
    mail_stop: String
    "Identifies the  name or number of the party's office."
    office: String
  }

  type OscalPerson implements OscalObject & Identity & OscalParty {
    # OscalObject
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
    # Identity
    "Identifies the name given to the party."
    name: String!
    "Identifies a brief description of the Party."
    description: String
    # OscalParty
    "Identifies the kind of party the object describes."
    party_type: PartyType!
    "Identifies a short common name, abbreviation, or acronym for the party."
    short_name: String
    "Identifies one or more external identifiers for a person or organization using a designated scheme. e.g. an Open Researcher and Contributor ID (ORCID)."
    external_ids: [ExternalReference]
    "Identifies a postal addresses for the location."
    address: CivicAddress
    "Identifies one or more email addresses for the location."
    email_addresses: EmailAddress
    "Identifies one or more telephone numbers used to contact the the location."
    telephone_numbers: [TelephoneNumber]
    "Identifies one or more references to a location."
    locations: [OscalLocation]
    "Identifies that the party object is a member of the organization."
    member_of_organizations: [OscalOrganization]
    "Identifies a mail stop associated with the party."
    mail_stop: String
    "Identifies the name or number of the party's office."
    office: String
    "Identifies the formal job title of a person."
    job_title: String
  }

  input OscalPersonAddInput {
      # OscalObject
      "Uniquely identifies this object."
      id: String!
      "Identifies the type of the Object."
      object_type: String!
      "Indicates the date and time at which the object was originally created."
      created: DateTime!
      "Indicates the date and time that this particular version of the object was last modified.""
      modified: DateTime!
      "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
      labels: [String]
      "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
      external_references: [ExternalReferenceAddInput]
      "Identifies one or more references to additional commentary on the Model."
      notes: [Note]
      # Identity
      "Identifies the name given to the party."
      name: String!
      "Identifies a brief description of the Party."
      description: String
      # OscalParty
      "Identifies the kind of party the object describes."
      party_type: PartyType!
      "Identifies a short common name, abbreviation, or acronym for the party."
      short_name: String
      "Identifies one or more external identifiers for a person or organization using a designated scheme. e.g. an Open Researcher and Contributor ID (ORCID)."
      external_ids: [ExternalReferenceAddInput]
      "Identifies a postal addresses for the location."
      address: CivicAddressAddInput
      "Identifies one or more email addresses for the location."
      email_addresses: EmailAddress
      "Identifies one or more telephone numbers used to contact the the location."
      telephone_numbers: [TelephoneNumberAddInput]
      "Identifies one or more references to a location."
      locations: [OscalLocationAddInput]
      "Identifies that the party object is a member of the organization."
      member_of_organizations: [OscalOrganizationAddInput]
      "Identifies a mail stop associated with the party."
      mail_stop: String
      "Identifies the name or number of the party's office."
      office: String
      "Identifies the formal job title of a person."
      job_title: String
  }

  type OscalResource implements OscalObject {
    # OscalObject
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
    # Resource
    "Identifies the type of resource represented."
    resource_type: ResourceType!
    "Identifies the version number of a published document."
    version: String
    "Identifies the publication date of a published document."
    published: DateTime
    "Identifies the name given to the party."
    name: String!
    "Identifies a brief description of the Party."
    description: String
    "Identifies references to previous versions of this document."
    document_ids: [OscalObject]
    "Identifies a citation consisting of end note text and optional structured bibliographic data."
    citations: [Citation]
    rlinks: [ExternalReference]
    base64: Base64Content
  }

  input OscalResourceAddInput {
    # OscalObject
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReferenceAddInput]
    "Identifies one or more references to additional commentary on the Model."
    notes: [NoteAddInput]
    # Resource
    "Identifies the type of resource represented."
    resource_type: ResourceType!
    "Identifies the version number of a published document."
    version: String
    "Identifies the publication date of a published document."
    published: DateTime
    "Identifies the name given to the party."
    name: String!
    "Identifies a brief description of the Party."
    description: String
    "Identifies references to previous versions of this document."
    document_ids: [OscalObject]
    "Identifies a citation consisting of end note text and optional structured bibliographic data."
    citations: [CitationAddInput]
    rlinks: [ExternalReferenceAddInput]
    base64: Base64ContentAddInput
  }

  type OscalResponsibleParty implements OscalObject {
    # OscalObject
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
    # ResponsibleParty
    "Identifies a reference to the role that the party is responsible for."
    role: Role!
    "Identifies one or more references to the parties that are responsible for performing the associated role."
    parties: [oscalParty]
  }

  input OscalResponsiblePartyAddInput {
    # OscalObject
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReferenceAddInput]
    "Identifies one or more references to additional commentary on the Model."
    notes: [NoteAddInput]
    # ResponsibleParty
    "Identifies a reference to the role that the party is responsible for."
    role: OscalRoleAddInput!
    "Identifies one or more references to the parties that are responsible for performing the associated role."
    parties: [OscalPartyAddInput!]!
  }

  "Defines identifying information about a function assumed or expected to be assumed by a party in a specific situation."
  type OscalRole implements OscalObject {
    # OscalObject
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
    # OscalRole
    "Identifies the unique identifier for a specific role instance."
    role_identifier: RoleType!
    "Identifies the name given to the role."
    name: String!
    "Identifies a short common name, abbreviation, or acronym for the role."
    short_name: String
    "Identifies a summary of the role's purpose and associated responsibilities."
    description: String
  }

  input OscalRoleAddInput {
    # Basic Object
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    # ExternalObject
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReferenceAddInput]
    "Identifies one or more references to additional commentary on the Model."
    notes: [NoteAddInput]
    # OscalRole
    "Identifies the unique identifier for a specific role instance."
    role_identifier: RoleType!
    "Identifies the name given to the role."
    name: String!
    "Identifies a short common name, abbreviation, or acronym for the role."
    short_name: String
    "Identifies a summary of the role's purpose and associated responsibilities."
    description: String
  }

  type Revision {
    "Identifies the name given to the document."
    name: String!
    "Identifies the date and time the document was published."
    published: DateTime
    "Identifies the date and time the document as last modified."
    last_modified: DateTime!
    "Identifies the current version of the document."
    version: String!
    "Identifies the OSCAL model version the document was authored against."
    oscal_version: String!
    "Identifies a list of revisions to the containing document."
  }

  "Characterizes the kind of location."
  enum LocationType {
    "A location that contains computing assets."
    data_center
  }

  "Characterizes the purpose of the location."
  enum LocationClass {
    "The location is a data-center used for normal operations."
    primary
    "The location is a data-center used for fail-over or backup operations."
    alternate
  }

  " Characterizes the type of the party."
  enum PartyType {
    "Indicates the party is a person"
    person
    "Indicates the party is an organization"
    organization
  }

  "Characterizes the type of the resource."
  enum ResourceType {
    "Indicates the resource is an organization's logo."
    logo
    "Indicates the resource represents an image."
    image
    "Indicates the resource represents an image of screen content."
    screen_shot
    "Indicates the resource represents an applicable law."
    law
    "Indicates the resource represents an applicable regulation."
    regulation
    "Indicates the resource represents an applicable standard."
    standard
    "Indicates the resource represents applicable guidance."
    external_guidance
    "Indicates the resource provides a list of relevant acronyms"
    acronyms
    "Indicates the resource cites relevant information"
    citation
    "Indicates the resource is a policy"
    policy
    "Indicates the resource is a procedure"
    procedure
    "Indicates the resource is guidance document related to the subject system of an SSP."
    system_guide
    "Indicates the resource is guidance document a user's guide or administrator's guide."
    users_guide
    "Indicates the resource is guidance document a administrator's guide."
    administrators_guide
    "Indicates the resource represents rules of behavior content"
    rules_of_behavior
    "Indicates the resource represents a plan"
    plan
    "Indicates the resource represents an artifact, such as may be reviewed by an assessor"
    artifact
    "Indicates the resource represents evidence, such as to support an assessment finding"
    evidence
    "Indicates the resource represents output from a tool"
    tool_output
    "Indicates the resource represents machine data, which may require a tool or analysis for interpretation or presentation"
    raw_data
    "Indicates the resource represents notes from an interview, such as may be collected during an assessment"
    interview_notes
    "Indicates the resource is a set of questions, possibly with responses"
    questionnaire
    "Indicates the resource is a report"
    report
    "Indicates the resource is a formal agreement between two or more parties"
    agreement
  }

  "Defined" the identifier for a specific role."
  enum RoleType {
    "Accountable for ensuring the asset is managed in accordance with organizational policies and procedures."
    asset_owner
    "Responsible for administering a set of assets."
    asset_administrator
    "Responsible for the configuration management processes governing changes to the asset."
    configuration_management
    "Responsible for providing information and support to users."
    help_desk
    " Responsible for responding to an event that could lead to loss of, or disruption to, an organization's operations, services or functions."
    incident_response
    "Member of the network operations center (NOC)."
    network_operations
    "Member of the security operations center (SOC)."
    security_operations
    "Responsible for the creation and maintenance of a component."
    maintainer
    "Organization responsible for providing the component, if this is different from the "maintainer" (e.g., a reseller)."
    provider
  }
`;

export default typeDefs ;