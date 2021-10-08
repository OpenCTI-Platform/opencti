import gql from 'graphql-tag' ;

const typeDefs = gql`
    enum FamilyType {
        windows
        linux
        macOS
        other
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
        softwareAdd(input: SoftwareAddInput): Software
        softwareDelete(id: String!): String!
        softwareEdit(id: String!, input: [EditInput]!, commitMessage: String): Software
    }


    # Query Types
    "Defines identifying information about an instance of software."
    type Software implements BasicObject & ExternalObject & Asset & ItAsset {
        # Basic Object
        id: String!
        object_type: String!
        # ExternalObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references: [ExternalReference]
        notes: [Note]
        # Asset
        name: String!
        description: String
        locations: [AssetLocation]!
        asset_id: String
        # responsible_parties: [ResponsibleParty]
        # IT Asset
        asset_type: AssetType!
        asset_tag: String
        serial_number: String
        vendor_name: String
        version: String
        release_date: DateTime
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
        # Software
        function: String
        cpe_identifier: String
        software_identifier: String
        patch_level: String
        installation_id: String
        license_key: String
    }

    "Defines identifying information about an instance of operating system software."
    type OperatingSystem implements BasicObject & ExternalObject & Asset & ItAsset {
        # Basic Object
        id: String!
        object_type: String!
        # ExternalObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references: [ExternalReference]
        notes: [Note]
        # Asset
        name: String!
        description: String
        locations: [AssetLocation]!
        asset_id: String
        # responsible_parties: [ResponsibleParty]
        # IT Asset
        asset_type: AssetType!
        asset_tag: String
        serial_number: String
        vendor_name: String
        version: String
        release_date: DateTime
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
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
    type ApplicationSoftware implements BasicObject & ExternalObject & Asset & ItAsset {
        # Basic Object
        id: String!
        object_type: String!
        # ExternalObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references: [ExternalReference]
        notes: [Note]
        # Asset
        name: String!
        description: String
        locations: [AssetLocation]!
        asset_id: String
        # responsible_parties: [ResponsibleParty]
        # IT Asset
        asset_type: AssetType!
        asset_tag: String
        serial_number: String
        vendor_name: String
        version: String
        release_date: DateTime
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
        # Software
        function: String
        cpe_identifier: String
        software_identifier: String
        patch_level: String
        installation_id: String
        license_key: String
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

    # Mutation Types
    input SoftwareAddInput {
        # Basic Object
        id: String!
        object_type: String!
        # ExternalObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references: [ExternalReferenceAddInput]
        notes: [NoteAddInput]
        # Asset
        name: String!
        description: String
        locations: [AssetLocationAddInput]!
        asset_id: String
        # responsible_parties: [ResponsibleParty]
        # IT Asset
        asset_type: AssetType!
        asset_tag: String
        serial_number: String
        vendor_name: String
        version: String
        release_date: DateTime
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
        # Software
        function: String
        cpe_identifier: String
        software_identifier: String
        patch_level: String
        installation_id: String
        license_key: String
    }

    input OperatingSystemAddInput {
        # Basic Object
        id: String!
        object_type: String!
        # ExternalObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references: [ExternalReferenceAddInput]
        notes: [NoteAddInput]
        # Asset
        name: String!
        description: String
        locations: [AssetLocationAddInput]!
        asset_id: String
        # responsible_parties: [ResponsibleParty]
        # IT Asset
        asset_type: AssetType!
        asset_tag: String
        serial_number: String
        vendor_name: String
        version: String
        release_date: DateTime
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
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
        # Basic Object
        id: String!
        object_type: String!
        # ExternalObject
        created: DateTime!
        modified: DateTime!
        labels: [String]
        external_references: [ExternalReferenceAddInput]
        notes: [NoteAddInput]
        # Asset
        name: String!
        description: String
        locations: [AssetLocationAddInput]!
        asset_id: String
        # responsible_parties: [ResponsibleParty]
        # IT Asset
        asset_type: AssetType!
        asset_tag: String
        serial_number: String
        vendor_name: String
        version: String
        release_date: DateTime
        implementation_point: ImplementationPoint!
        operational_status: OperationalStatus!
        # Software
        function: String
        cpe_identifier: String
        software_identifier: String
        patch_level: String
        installation_id: String
        license_key: String
    }
`;

export default typeDefs ;