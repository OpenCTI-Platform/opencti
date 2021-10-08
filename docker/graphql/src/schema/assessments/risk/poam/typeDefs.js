import gql from 'graphql-tag' ;

const typeDefs = gql`

  type POAM implements OscalObject &  Model {
    # OSCAL Object
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
    # Backmatter
    resources: [OscalResource]
    "Identifies a unique identifier for the system describe by the System Security Plan."
    system_id: String
    "Identifies the identification system from which the provided identifier was assigned."
    system_identifier_type: SystemIDType
    "Identifies components and inventory-items to be defined within the POA&M for circumstances where no OSCAL-based SSP exists, or is not delivered with the POA&M."
    local_definitions: PoamLocalDefinition
    observations: [Observation]
    risks: [Risk]
    poam_items: [PoamItem]
  }

  type PoamLocalDefinition {
    components: [Component]
    inventory_items: [InventoryItem]
    notes: [Note]
  }

  type PoamItem implements OscalObject {
    # OSCAL Object
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
    # Finding
    "Identifies the name for this POA&M item."
    name: String!
    "Identifies a human-readable description of the POA&M item."
    description: String!
    "Identifies one or more sources of the finding, such as a tool, interviewed person, or activity."
    origins: [Origin]
    # "Identifies an assessor's conclusions regarding the degree to which an objective is satisfied."
    # target: FindingTarget
    # "Identifies a reference to the implementation statement in the SSP to which this finding is related."
    # implementation_statement: ImplementationStatement
    "Relates the finding to a set of referenced observations that were used to determine the finding."
    related_observations: [Observation]
    "Relates the finding to a set of referenced risks that were used to determine the finding."
    related_risks: [Risk]
    # POAM Item
    "Indicates the risk has been excepted"
    accepted_risk: Boolean
  }

  enum SystemIDType {
    "FedRAMP-assigned identifier"
    https://fedramp.gov
    "A Universally Unique Identifier (UUID)"
    https://ietf.org/rfc/rfc4122
  }

`;

export default typeDefs ;
