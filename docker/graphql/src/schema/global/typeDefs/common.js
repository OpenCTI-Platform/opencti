import gql from 'graphql-tag';

const common = gql`
    interface BasicObject {
        id: String!
        object_type: String!
    }

    interface ExternalObject {
      created: DateTime!
      modified: DateTime!
      labels: [String]
      external_references: [ExternalReference]
      notes: [Note]
    }

    type Note implements BasicObject & ExternalObject {
      # Basic Object
      id: String!
      object_type: String!
      # ExternalObject
      created: DateTime!
      modified: DateTime!
      labels: [String]
      external_references: [ExternalReference]
      notes: [Note]
      # Note
      abstract: String
      content: String!
      authors: [String]
      object_refs: [String]
    }

    input NoteAddInput {
      # Basic Object
      id: String!
      object_type: String!
      # ExternalObject
      created: DateTime!
      modified: DateTime!
      labels: [String]
      external_references: [ExternalReferenceAddInput]
      notes: [NoteAddInput]
      # Note
      abstract: String
      content: String!
      authors: [String]
      object_refs: [String!]!
    }

    interface Location {
      # Basic Object
      id: String!
      object_type: String!
      # ExternalObject
      created: DateTime!
      modified: DateTime!
      labels: [String]
      external_references: [ExternalReference]
      notes: [Note]
      # Location
      name: String!
      description: String
    }
    
    input LocationAddInput {
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
    }

    interface Identity {
      # Basic Object
      id: String!
      object_type: String!
      # ExternalObject
      created: DateTime!
      modified: DateTime!
      labels: [String]
      external_references: [ExternalReference]
      notes: [Note]
      # Identity
      name: String!
      description: String
    }

    type ExternalReference {
      source_name: String!
      description: String
      external_id: String
      reference_purpose: ReferencePurposeType
      media_type: String
      url: URL
      hashes: [HashInfo]
    }

    input ExternalReferenceAddInput {
      source_name: String!
      description: String
      external_id: String
      reference_purpose: ReferencePurposeType
      media_type: String
      url: URL
      hashes: [HashInfoAddInput]
    }

    type HashInfo {
      algorithm: HashAlgorithm!
      value: String!
    }

    input HashInfoAddInput {
      algorithm: HashAlgorithm!
      value: String!
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

    enum ReferencePurposeType {
      "Identifies a reference to an external resource."
      reference
      "Identifies the authoritative location for this file."
      canonical
      "Identifies an alternative location or format for this file."
      alternative
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

    enum OperationalStatus {
        operational_status
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
