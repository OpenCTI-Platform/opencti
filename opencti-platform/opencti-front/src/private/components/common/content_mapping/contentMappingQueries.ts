import { graphql } from 'react-relay';

// Everything the review needs about the container, refetched after each action.
export const contentMappingReviewQuery = graphql`
  query contentMappingQueriesReviewQuery($id: String!) {
    container(id: $id) {
      id
      standard_id
      entity_type
      confidence
      draftVersion {
        draft_id
      }
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
      ... on Report {
        name
        description
        contentField: content
        content_mapping
        content_mapping_review
      }
      ... on Case {
        name
        description
        contentField: content
        content_mapping
        content_mapping_review
      }
      ... on Grouping {
        name
        description
        contentField: content
        content_mapping
        content_mapping_review
      }
      ... on StixCoreObject {
        importFiles(first: 100) {
          edges {
            node {
              id
              name
              metaData {
                mimetype
              }
            }
          }
        }
      }
      objects(first: 1000, all: true) {
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
            ... on StixCoreRelationship {
              id
              standard_id
              entity_type
              relationship_type
              description
              from {
                ... on StixCoreObject {
                  id
                  entity_type
                  representative {
                    main
                  }
                }
              }
              to {
                ... on StixCoreObject {
                  id
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
  }
`;

export const contentMappingAnalysisQuery = graphql`
  query contentMappingQueriesAnalysisQuery($id: ID!, $contentSource: String!, $contentType: AnalysisContentType!) {
    stixCoreObjectAnalysis(id: $id, contentSource: $contentSource, contentType: $contentType) {
      ... on MappingAnalysis {
        analysisStatus
        analysisDate
        mappedEntities {
          matchedString
          matchedEntity {
            id
            standard_id
            entity_type
            representative {
              main
            }
          }
        }
        unresolvedEntities {
          matchedString
          standardId
          entityType
        }
      }
    }
    connectorsForAnalysis {
      id
    }
  }
`;

// Existing objects matching a selected value: by name, alias or observable value (search is refanged server-side).
export const contentMappingSearchQuery = graphql`
  query contentMappingQueriesSearchQuery($search: String!, $filters: FilterGroup) {
    stixCoreObjects(search: $search, filters: $filters, first: 6) {
      edges {
        node {
          id
          standard_id
          entity_type
          representative {
            main
          }
          containersNumber {
            total
          }
          ... on Malware { aliases }
          ... on IntrusionSet { aliases }
          ... on ThreatActor { aliases }
          ... on Tool { aliases }
          ... on Campaign { aliases }
          ... on AttackPattern { aliases x_mitre_id }
          ... on Organization { x_opencti_aliases }
          ... on Location { x_opencti_aliases }
        }
      }
    }
  }
`;

// Objects already in the platform under the names to create: possible duplicates (DTAG, issue B).
export const contentMappingDuplicatesQuery = graphql`
  query contentMappingQueriesDuplicatesQuery($filters: FilterGroup) {
    stixCoreObjects(filters: $filters, first: 200) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
        }
      }
    }
  }
`;

export const contentMappingFieldPatchMutation = graphql`
  mutation contentMappingQueriesFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(input: $input) {
        id
      }
    }
  }
`;

export const contentMappingRelationsAddMutation = graphql`
  mutation contentMappingQueriesRelationsAddMutation($id: ID!, $toIds: [StixRef!]!) {
    stixCoreObjectEdit(id: $id) {
      relationsAdd(input: { relationship_type: "object", toIds: $toIds }) {
        id
      }
    }
  }
`;

export const contentMappingRelationDeleteMutation = graphql`
  mutation contentMappingQueriesRelationDeleteMutation($id: ID!, $toId: StixRef!) {
    stixCoreObjectEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: "object") {
        id
      }
    }
  }
`;

export const contentMappingDeleteMutation = graphql`
  mutation contentMappingQueriesDeleteMutation($id: ID!) {
    stixCoreObjectEdit(id: $id) {
      delete
    }
  }
`;

export const contentMappingDomainObjectAddMutation = graphql`
  mutation contentMappingQueriesDomainObjectAddMutation($input: StixDomainObjectAddInput!) {
    stixDomainObjectAdd(input: $input) {
      id
      standard_id
      entity_type
      representative {
        main
      }
    }
  }
`;

export const contentMappingObservableAddMutation = graphql`
  mutation contentMappingQueriesObservableAddMutation(
    $type: String!
    $objectMarking: [String]
    $objectLabel: [String]
    $createdBy: String
    $IPv4Addr: IPv4AddrAddInput
    $IPv6Addr: IPv6AddrAddInput
    $DomainName: DomainNameAddInput
    $Url: UrlAddInput
    $EmailAddr: EmailAddrAddInput
    $StixFile: StixFileAddInput
    $MacAddr: MacAddrAddInput
    $AutonomousSystem: AutonomousSystemAddInput
  ) {
    stixCyberObservableAdd(
      type: $type
      objectMarking: $objectMarking
      objectLabel: $objectLabel
      createdBy: $createdBy
      IPv4Addr: $IPv4Addr
      IPv6Addr: $IPv6Addr
      DomainName: $DomainName
      Url: $Url
      EmailAddr: $EmailAddr
      StixFile: $StixFile
      MacAddr: $MacAddr
      AutonomousSystem: $AutonomousSystem
    ) {
      id
      standard_id
      entity_type
      representative {
        main
      }
    }
  }
`;

export const contentMappingAskAnalysisMutation = graphql`
  mutation contentMappingQueriesAskAnalysisMutation($id: ID!, $contentSource: String!, $contentType: AnalysisContentType!) {
    stixCoreObjectEdit(id: $id) {
      askAnalysis(contentSource: $contentSource, contentType: $contentType) {
        id
      }
    }
  }
`;

export const contentMappingRelationshipDescriptionMutation = graphql`
  mutation contentMappingQueriesRelationshipDescriptionMutation($id: ID!, $input: [EditInput]!) {
    stixCoreRelationshipEdit(id: $id) {
      fieldPatch(input: $input) {
        id
      }
    }
  }
`;
