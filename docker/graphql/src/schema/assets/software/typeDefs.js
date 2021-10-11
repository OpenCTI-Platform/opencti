import gql from 'graphql-tag' ;

const typeDefs = gql`
  input SoftwareFiltering {
      key: SoftwareFilter!
      values: [String]
      operator: String
      filterMode: FilterMode 
  }

  # Query Extensions
  extend type Query {
      softwareList(
          first: Int
          offset: Int
          orderedBy: SoftwareOrdering
          orderMode: OrderingMode
          filters: [SoftwareFiltering]
          filterMode: FilterMode
          search: String
        ): [Software]
      software(id: String!): Software
  }

  extend type Mutation {
      createSoftware(input: SoftwareAddInput): Software
      deleteSoftware(id: String!): String!
      editSoftware(id: String!, input: [EditInput]!, commitMessage: String): Software
      createOperatingSystem(input: OperatingSystemAddInput): OperatingSystem
      deleteOperatingSystem(id: String!): String!
      editOperatingSystem(id: String!, input: [EditInput]!, commitMessage: String): OperatingSystem
      createApplicationSoftware(input: OperatingSystemAddInput): ApplicationSoftware
      deleteApplicationSoftware(id: String!): String!
      editApplicationSoftware(id: String!, input: [EditInput]!, commitMessage: String): ApplicationSoftware
  }


  # Query Types
  "Defines identifying information about an instance of software."
  type Software implements RootObject & CoreObject & Asset & ItAsset {
      # Root Object
      id: String!
      entity_type: String!
      # CoreObject
      created: DateTime!
      modified: DateTime!
      labels: [String]
      # Asset
      asset_id: String
      name: String!
      description: String
      locations: [Location]
      external_references( first: Int ): ExternalReferenceConnection
      notes( first: Int ): NoteConnection
      # ItAsset
      asset_tag: String
      asset_type: AssetType!
      serial_number: String
      vendor_name: String
      version: String
      release_date: DateTime
      implementation_point: ImplementationPoint!
      operational_status: OperationalStatus!
      # responsible_parties: [ResponsibleParty]
      # Software
      function: String
      cpe_identifier: String
      software_identifier: String
      patch_level: String
      installation_id: String
      license_key: String
  }

  "Defines identifying information about an instance of operating system software."
  type OperatingSystem implements RootObject & CoreObject & Asset & ItAsset {
      # Root Object
      id: String!
      entity_type: String!
      # CoreObject
      created: DateTime!
      modified: DateTime!
      labels: [String]
      # Asset
      asset_id: String
      name: String!
      description: String
      locations: [Location]
      external_references( first: Int ): ExternalReferenceConnection
      notes( first: Int ): NoteConnection
      # ItAsset
      asset_tag: String
      asset_type: AssetType!
      serial_number: String
      vendor_name: String
      version: String
      release_date: DateTime
      implementation_point: ImplementationPoint!
      operational_status: OperationalStatus!
      # responsible_parties: [ResponsibleParty]
      # Software
      function: String
      cpe_identifier: String
      software_identifier: String
      patch_level: String
      installation_id: String
      license_key: String
      # Operating System
      family: FamilyType
  }

  "Defines identifying information about an instance of application software."
  type ApplicationSoftware implements RootObject & CoreObject & Asset & ItAsset {
      # Root Object
      id: String!
      entity_type: String!
      # CoreObject
      created: DateTime!
      modified: DateTime!
      labels: [String]
      # Asset
      asset_id: String
      name: String!
      description: String
      locations: [Location]
      external_references( first: Int ): ExternalReferenceConnection
      notes( first: Int ): NoteConnection
      # ItAsset
      asset_tag: String
      asset_type: AssetType!
      serial_number: String
      vendor_name: String
      version: String
      release_date: DateTime
      implementation_point: ImplementationPoint!
      operational_status: OperationalStatus!
      # responsible_parties: [ResponsibleParty]
      # Software
      function: String
      cpe_identifier: String
      software_identifier: String
      patch_level: String
      installation_id: String
      license_key: String
  }

  # Mutation Types
  input SoftwareAddInput {
      labels: [String]
      # Asset
      asset_id: String
      name: String!
      description: String
      # ItAsset
      asset_tag: String
      asset_type: AssetType!
      serial_number: String
      vendor_name: String
      version: String
      release_date: DateTime
      implementation_point: ImplementationPoint!
      operational_status: OperationalStatus!
      # responsible_parties: [ResponsibleParty]
      # Software
      function: String
      cpe_identifier: String
      software_identifier: String
      patch_level: String
      installation_id: String
      license_key: String
  }

  input OperatingSystemAddInput {
      labels: [String]
      # Asset
      asset_id: String
      name: String!
      description: String
      # ItAsset
      asset_tag: String
      asset_type: AssetType!
      serial_number: String
      vendor_name: String
      version: String
      release_date: DateTime
      implementation_point: ImplementationPoint!
      operational_status: OperationalStatus!
      # responsible_parties: [ResponsibleParty]
      # Software
      function: String
      cpe_identifier: String
      software_identifier: String
      patch_level: String
      installation_id: String
      license_key: String
      # Operating System
      family: FamilyType
  }

  input ApplicationSoftwareAddInput {
      labels: [String]
      # Asset
      asset_id: String
      name: String!
      description: String
      # ItAsset
      asset_tag: String
      asset_type: AssetType!
      serial_number: String
      vendor_name: String
      version: String
      release_date: DateTime
      implementation_point: ImplementationPoint!
      operational_status: OperationalStatus!
      # responsible_parties: [ResponsibleParty]
      # Software
      function: String
      cpe_identifier: String
      software_identifier: String
      patch_level: String
      installation_id: String
      license_key: String
  }

  enum FamilyType {
      windows
      linux
      macOS
      other
  }

  # Pagination Types
  type SoftwareConnection {
      pageInfo: PageInfo!
      edges: [SoftwareEdge]
  }

  type SoftwareEdge {
      cursor: String!
      node: Software!
  }

  enum SoftwareOrdering {
      name
      asset_type
      asset_id
      labels
  }

  enum SoftwareFilter {
      name
      asset_type
      asset_id
      labels
  }

`;

export default typeDefs ;