import gql from 'graphql-tag';

const scalars = gql`
  scalar ConstraintString   # npm graphql-constraint-directive
  scalar ConstraintNumber   # npm graphql-constraint-directive
  scalar Date               # graphql-scalars
  scalar DateTime           # graphql-scalars
  scalar EmailAddress       # graphql-scalars
  scalar IPv4               # graphql-scalars
  scalar IPv6               # graphql-scalars
  scalar Longitude          # graphql-scalars
  scalar Latitude           # graphql-scalars
  scalar MAC                # graphql-scalars
  scalar NonNegativeInt     # graphql-scalars
  scalar PositiveInt        # graphql-scalars
  scalar PhoneNumber        # graphql-scalars
  scalar PositiveInt        # graphql-scalars
  scalar Port               # graphql-scalars
  scalar PostalCode         # graphql-scalars
  scalar URL                # graphql-scalars
  scalar UUID               # graphql-scalars
  scalar Void               # graphql-scalars
`;

export default scalars;
