import { graphql } from 'react-relay';

// eslint-disable-next-line import/prefer-default-export
export const parseWorkErrorsQuery = graphql`
    query ParseWorkErrorsQuerySearchQuery($ids: [Any!]!) {
        stixObjectOrStixRelationships(
            filters: {
                mode: or
                filterGroups: []
                filters: [
                    {
                        key: "standard_id"
                        values: $ids
                        mode: or
                    }
                ]
            }
        ) {
            edges {
                node {
                    ... on StixCoreObject {
                        id
                        standard_id
                        entity_type
                        representative {
                            main
                        }
                    }
                    ... on StixRelationship {
                        id
                        standard_id
                        entity_type
                        representative {
                            main
                        }
                        from {
                            ... on StixCoreObject {
                                id
                                standard_id
                                entity_type
                                representative {
                                    main
                                }
                            }
                            ... on StixRelationship {
                                id
                                standard_id
                                entity_type
                                representative {
                                    main
                                }
                            }
                        }
                        to {
                            ... on StixCoreObject {
                                id
                                standard_id
                                entity_type
                                representative {
                                    main
                                }
                            }
                            ... on StixRelationship {
                                id
                                standard_id
                                entity_type
                                representative {
                                    main
                                }
                            }
                        }
                    }
                }
            }
        }
    }
`;
