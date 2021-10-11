import gql from 'graphql-tag';

const common = gql`
  # declares the query entry-points for this type
  extend type Query {
    note(id: String!): Note
    noteList( 
          first: Int
          offset: Int
          orderedBy: NotesOrdering
          orderMode: OrderingMode
          filters: [NotesFiltering]
          filterMode: FilterMode
          search: String
        ): NoteConnection
  }

  # declares the mutation entry-points for this type
  extend type Mutation {
    addReference(input: ReferenceAddInput): Boolean
    removeReference( input: ReferenceAddInput): Boolean
    createNote(input: NoteAddInput): Note
    deleteNote(id: String!): String!
    editNote(id: String!, input: [EditInput]!, commitMessage: String): Note
  }

  # Type Definitions
    interface RootObject {
        id: String!
        entity_type: String!
    }

    interface CoreObject {
      created: DateTime!
      modified: DateTime!
      labels: [String]
      external_references( first: Int ): ExternalReferenceConnection
      notes( first: Int ): NoteConnection
    }

    "Reference input to add a reference between two different objects"
    input ReferenceAddInput {
      field_name: String!  # this is the name of the field
      from_id: String!
      to_id: String!
    }

    ############## ExternalReferences
    enum ExternalReferencesOrdering {
      source_name
      url
      hash
      external_id
      created
      modified
      created_at
      updated_at
    }
    enum ExternalReferencesFilter {
      url
      source_name
      external_id
    }
    input ExternalReferencesFiltering {
      key: ExternalReferencesFilter!
      values: [String]
      operator: String
      filterMode: FilterMode
    }

    # Pagination Types
    type ExternalReferenceConnection {
      pageInfo: PageInfo!
      edges: [ExternalReferenceEdge]
    }
    type ExternalReferenceEdge {
      cursor: String!
      node: ExternalReference!
    }

    type ExternalReference implements RootObject {
      id: String! # internal_id
      entity_type: String!
      # ExternalReference
      created: DateTime
      modified: DateTime
      source_name: String!
      description: String
      url: URL
      hashes: [HashInfo]
      external_id: String
      # OSCAL Link
      reference_purpose: ReferencePurposeType
      media_type: String
    }

    input ExternalReferenceAddInput {
      source_name: String!
      description: String
      url: URL
      hashes: [HashInfoAddInput]
      # OSCAL Link
      reference_purpose: ReferencePurposeType
      media_type: String
    }

    type HashInfo {
      algorithm: HashAlgorithm!
      value: String!
    }

    input HashInfoAddInput {
      algorithm: HashAlgorithm!
      value: String!
    }

    enum ReferencePurposeType {
      "Identifies a reference to an external resource."
      reference
      "Identifies the authoritative location for this file."
      canonical
      "Identifies an alternative location or format for this file."
      alternative
    }

    enum HashAlgorithm {
      "The SHA-224 algorithm as defined by NIST FIPS 180-4."
      SHA_224
      "The SHA-256 algorithm as defined by NIST FIPS 180-4."
      SHA_256
      "The SHA-384 algorithm as defined by NIST FIPS 180-4."
      SHA_384
      "The SHA-512 algorithm as defined by NIST FIPS 180-4."
      SHA_512
      "The SHA3-224 algorithm as defined by NIST FIPS 202."
      SHA3_224
      "The SHA3-256 algorithm as defined by NIST FIPS 202."
      SHA3_256
      "The SHA3-384 algorithm as defined by NIST FIPS 202."
      SHA3_384
      "The SHA3-512 algorithm as defined by NIST FIPS 202."
      SHA3_512
    }

    type Note implements RootObject {
      # Root Object
      id: String!
      entity_type: String!
      # CoreObject
      created: DateTime!
      modified: DateTime!
      labels: [String]
      external_references( first: Int ): ExternalReferenceConnection
      # Note
      abstract: String
      content: String!
      authors: [String]
    }

    input NoteAddInput {
      # Note
      abstract: String
      content: String!
      authors: [String]
    }

    enum NotesOrdering {
      created
      modified
      labels
    }

    enum NotesFilter {
      abstract
      authors
      created
      modified
      labels
    }

    input NotesFiltering {
      key: NotesFilter!
      values: [String]!
      operator: String
      filterMode: FilterMode
    }

    # Pagination Types
    type NoteConnection {
      pageInfo: PageInfo!
      edges: [NoteEdge]
    }

    type NoteEdge {
      cursor: String!
      node: Note!
    }

    interface Location {
      # Root Object
      id: String!
      entity_type: String!
      # CoreObject
      created: DateTime!
      modified: DateTime!
      labels: [String]
      external_references( first: Int ): ExternalReferenceConnection
      notes( first: Int ): NoteConnection
      # Location
      name: String!
      description: String
    }
    
    input LocationAddInput {
      labels: [String]
      # Location
      location_type: LocationType
      name: String!
      description: String
    }

    interface Identity {
      # Root Object
      id: String!
      entity_type: String!
      # CoreObject
      created: DateTime!
      modified: DateTime!
      labels: [String]
      external_references( first: Int ): ExternalReferenceConnection
      notes( first: Int ): NoteConnection
      # Identity
      name: String!
      description: String
    }

    enum LocationType {
      geo_location
      city
      country
      region
      civic_address
    }

    enum Region {
      africa
      eastern_africa
      middle_africa
      norther_africa
      southern_africa
      western_africa
      americas
      caribbean
      central_america
      latin_america_caribbean
      norther_america
      south_america
      asia
      central_asia
      eastern_asia
      southern_asia
      south_eastern_asia
      western_asia
      europe
      eastern_europe
      northern_europe
      southern_europe
      western_europe
      oceania
      antarctica
      australia_new_zealand
      melanesia
      micronesia
      polynesia
    }


    type PageInfo {
      startCursor: String!
      endCursor: String!
      hasNextPage: Boolean!
      hasPreviousPage: Boolean!
      globalCount: Int!
    }
    
    enum OrderingMode {
      asc
      desc
    }

    enum FilterMode {
      and
      or
    }

    enum EditOperation {
      add
      replace
      remove
    }

    # Editing
    input EditInput {
      key: String!              # Field name to change
      value: [String]!          # Values to apply
      operation: EditOperation  # Undefined = REPLACE
    }

    enum OperationalStatus {
        operational
        under_development
        under_major_modification
        disposition
        other
    }

    enum ImplementationPoint {
      internal
      external
    }

    type CivicAddress {
        address_type: UsageType
        street_address: String
        city: String
        administrative_area: String
        country: String
        postal_code: PostalCode
    }

    input CivicAddressAddInput {
      address_type: UsageType
      street_address: String
      city: String
      administrative_area: String
      country: String
      postal_code: PostalCode
    }

    enum UsageType {
      home
      office
      mobile
    }

    type TelephoneNumber {
      usage_type: UsageType
      phone_number: PhoneNumber
    }

    input TelephoneNumberAddInput {
      usage_type: UsageType
      phone_number: PhoneNumber
    }

    type ContactInfo {
      email_addresses: [EmailAddress]
      telephone_numbers: [TelephoneNumber]
    }
`;

export default common;
