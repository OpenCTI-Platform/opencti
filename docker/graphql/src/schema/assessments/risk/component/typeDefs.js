import gql from 'graphql-tag' ;

const typeDefs = gql`
  ""
  type Software implements OscalObject & Component {
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
    # Software

  }
`;

export default typeDefs ;
