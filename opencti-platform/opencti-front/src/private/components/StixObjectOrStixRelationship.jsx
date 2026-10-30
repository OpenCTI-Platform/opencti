import { Navigate, useParams } from 'react-router';
import { graphql } from 'react-relay';
import { QueryRenderer } from '../../relay/environment';
import Loader from '../../components/Loader';
import ErrorNotFound from '../../components/ErrorNotFound';
import Box from '@mui/material/Box';
import { useComputeLink } from '../../utils/hooks/useAppData';

export const stixObjectOrStixRelationshipStixObjectOrStixRelationshipQuery = graphql`
  query StixObjectOrStixRelationshipStixObjectOrStixRelationshipQuery(
    $id: String!
  ) {
    stixObjectOrStixRelationship(id: $id) {
      ... on StixCoreObject {
        id
        parent_types
        entity_type
      }
      ... on ExternalReference {
        id
        parent_types
        entity_type
      }
      ... on SecurityCoverageResult {
        resultOf {
          id
        }
      }
      ... on StixCoreRelationship {
        id
        parent_types
        entity_type
        relationship_type
        from {
          ... on StixCoreObject {
            id
            parent_types
            entity_type
          }
          ... on StixCoreRelationship {
            id
            parent_types
            entity_type
            relationship_type
          }
        }
        to {
          ... on StixCoreObject {
            id
            parent_types
            entity_type
          }
          ... on StixCoreRelationship {
            id
            parent_types
            entity_type
            relationship_type
          }
        }
      }
      ... on StixSightingRelationship {
        id
        parent_types
        entity_type
        relationship_type
        from {
          ... on StixCoreObject {
            id
            parent_types
            entity_type
          }
          ... on StixCoreRelationship {
            id
            parent_types
            entity_type
            relationship_type
          }
        }
        to {
          ... on StixCoreObject {
            id
            parent_types
            entity_type
          }
          ... on StixCoreRelationship {
            id
            parent_types
            entity_type
            relationship_type
          }
        }
      }
    }
  }
`;

const StixObjectOrStixRelationship = () => {
  const { id } = useParams();
  const computeLink = useComputeLink();

  return (
    <Box sx={{ margin: 0, padding: 0 }}>
      <QueryRenderer
        query={stixObjectOrStixRelationshipStixObjectOrStixRelationshipQuery}
        variables={{ id }}
        render={({ props }) => {
          if (props) {
            if (props.stixObjectOrStixRelationship) {
              const { stixObjectOrStixRelationship: node } = props;
              const redirectLink = computeLink(node);
              if (redirectLink) {
                return <Navigate exact from={`/id/${id}`} to={redirectLink} replace={true} />;
              }
            }
            return <ErrorNotFound />;
          }
          return <Loader />;
        }}
      />
    </Box>
  );
};

export default StixObjectOrStixRelationship;
