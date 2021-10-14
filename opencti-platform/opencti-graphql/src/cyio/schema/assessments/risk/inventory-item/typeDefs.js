import gql from 'graphql-tag' ;

const typeDefs = gql`
  # declares the query entry-points for this type
  extend type Query {
    inventoryItem(id: ID!): InventoryItem
    inventoryItemList( 
          first: Int
          offset: Int
          orderedBy: InventoryItemsOrdering
          orderMode: OrderingMode
          filters: [InventoryItemsFiltering]
          filterMode: FilterMode
          search: String
        ): InventoryItemConnection
  }

  # declares the mutation entry-points for this type
  extend type Mutation {
    createInventoryItem(input: InventoryItemAddInput): InventoryItem
    deleteInventoryItem(id: ID!): String!
    editInventory(id: ID!, input: [EditInput]!, commitMessage: String): InventoryItem
  }


#####   Inventory Item Component 
##
  "Defines identifying information about a single managed inventory item within the system."
  interface InventoryItem {
    # BasicObject
    "Uniquely identifies this object."
    id: ID!
    "Identifies the identifier defined by the standard."
    standard_id: String!
    "Identifies the type of the Object."
    entity_type: String!
    "Identifies the parent types of this object."
    parent_types: [String]!
    # CoreObject
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified."
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    # OscalObject
    "Identifies a list of CyioExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references( first: Int ): CyioExternalReferenceConnection
    "Identifies one or more references to additional commentary on the Model."
    notes( first: Int ): CyioNoteConnection
    "Identifies one or more relationships to other entities."
    relationships(
      first: Int
      offset: Int
      orderedBy: OscalRelationshipsOrdering
      orderMode: OrderingMode
      filters: [OscalRelationshipsFiltering]
      filterMode: FilterMode
      search: String 
    ): OscalRelationshipConnection
    # Inventory Item
    "Indicates the asset's function, such as Router, Storage Array, DNS Server."
    asset_type: AssetType!
    "Identifies an organizationally specific identifier that is used to uniquely identify a logical or tangible item by the organization that owns the item."
    asset_id: String
    "Identifies an asset tag assigned by the organization responsible for maintaining the logical or tangible item."
    asset_tag: String
    "Indicates the serial number for the asset."
    serial_number: String
    "Identifies a description of the component, including information about its function."
    description: String!
    "Identifies the  model of the component."
    model: String
    "Identifies the name of the company or organization"
    vendor_name: String
    "Identifies whether the asset can be check with an authenticated scan"
    allows_authenticated_scans: Boolean
    "Identifies whether the asset is publicly accessible"
    is_publicly_accessible: Boolean
    "Indicates if the asset is subjected to network scans"
    is_scanned: Boolean
    "Identifies whether the asset is virtualized"
    is_virtual: Boolean
    "Indicates the Internet Protocol v4 Addresses of the asset"
    ipv4_address: [IpV4Address!]
    "Indicates the Internet Protocol v4 Addresses of the asset"
    ipv6_address: [IpV6Address!]
    "Indicates the media access control (MAC) address for the asset."
    mac_address: [MAC!]
    "Indicates the full-qualified domain name (FQDN) of the asset."
    fqdn: String
    "Indicates the NetBIOS name for the asset."
    netbios_name: String
    "Indicates the Uniform Resource Identifier (URI) for the asset."
    uri: URL
    "Identifies the network identifier of the asset."
    network_id: String
    "Identifies the Virtual LAN identifier of the asset."
    vlan_id: String
    "Identifies The name of the baseline configuration for the asset."
    baseline_configuration_name: String
    "Identifies the function provided by the asset for the system."
    function: String
    "Identifies one or more references to a set of organizations or persons that have responsibility for performing a referenced role in the context of the containing object."
    responsible_parties: [OscalResponsibleParty]
    "Indicates the physical location of the asset's hardware (e.g., Data Center ID, Cage#, Rack#, or other meaningful location identifiers)."
    physical_location: [OscalLocation]
    "Identifies the set of components that are implemented in a given system inventory item."
    implemented_components: [Component]
  }

  # Mutation Types
  input InventoryItemAddInput {
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    # Inventory Item
    "Indicates the asset's function, such as Router, Storage Array, DNS Server."
    asset_type: AssetType!
    "Identifies an organizationally specific identifier that is used to uniquely identify a logical or tangible item by the organization that owns the item."
    asset_id: String
    "Identifies an asset tag assigned by the organization responsible for maintaining the logical or tangible item."
    asset_tag: String
    "Indicates the serial number for the asset."
    serial_number: String
    "Identifies a description of the component, including information about its function."
    description: String!
    "Identifies the  model of the component."
    model: String
    "Identifies the name of the company or organization"
    vendor_name: String
    "Identifies whether the asset can be check with an authenticated scan"
    allows_authenticated_scans: Boolean
    "Identifies whether the asset is publicly accessible"
    is_publicly_accessible: Boolean
    "Indicates if the asset is subjected to network scans"
    is_scanned: Boolean
    "Identifies whether the asset is virtualized"
    is_virtual: Boolean
    "Indicates the Internet Protocol v4 Addresses of the asset"
    ipv4_address: [IpV4AddressAddInput!]
    "Indicates the Internet Protocol v4 Addresses of the asset"
    ipv6_address: [IpV6AddressAddInput!]
    "Indicates the media access control (MAC) address for the asset."
    mac_address: [MAC!]
    "Indicates the full-qualified domain name (FQDN) of the asset."
    fqdn: String
    "Indicates the NetBIOS name for the asset."
    netbios_name: String
    "Indicates the Uniform Resource Identifier (URI) for the asset."
    uri: URL
    "Identifies the network identifier of the asset."
    network_id: String
    "Identifies the Virtual LAN identifier of the asset."
    vlan_id: String
    "Identifies The name of the baseline configuration for the asset."
    baseline_configuration_name: String
    "Identifies the function provided by the asset for the system."
    function: String
  }

  # Pagination Types
  type InventoryItemConnection {
    pageInfo: PageInfo!
    edges: [InventoryItemEdge]
  }

  type InventoryItemEdge {
    cursor: String!
    node: InventoryItem!
  }

  # Filtering Types
  input InventoryItemsFiltering {
    key: InventoryItemFilter!
    values: [String]!
    operator: String
    filterMode: FilterMode
  }

  enum InventoryItemsOrdering {
    asset_type
    created
    modified
    labels
  }

  enum InventoryItemFilter {
    asset_type
    created
    modified
    labels
  }

  # union InventoryItemTypes = 

`;

export default typeDefs ;
