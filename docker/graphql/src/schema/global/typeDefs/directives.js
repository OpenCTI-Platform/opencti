import gql from 'graphql-tag';

const directives = gql`
    directive @constraint(
        minLength: Int
        maxLength: Int
        startsWith: String
        endsWith: String
        notContains: String
        pattern: String
        format: String

        # number constraints
        min: Int
        max: Int
        exclusiveMin: Int
        exclusiveMax: Int
        multipleOf: Int
    ) on INPUT_FIELD_DEFINITION

    # directive @rateLimit(
    #     max: Int
    #     window: String
    #     message: String
    #     identityArgs: [String]
    # ) on FIELD_DEFINITION
`;
export default directives;
