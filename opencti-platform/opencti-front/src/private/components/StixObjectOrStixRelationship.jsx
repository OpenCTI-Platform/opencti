import { Navigate, useParams } from 'react-router-dom';
import { graphql } from 'react-relay';
import { QueryRenderer } from '../../relay/environment';
import Loader from '../../components/Loader';
import ErrorNotFound from '../../components/ErrorNotFound';
import makeStyles from '@mui/styles/makeStyles';
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

const useStyles = makeStyles({
  container: {
    margin: 0,
    padding: 0,
  },
});

const StixObjectOrStixRelationship = () => {
  const classes = useStyles();
  const { id } = useParams();
  const computeLink = useComputeLink();

  return (
    <div className={classes.container}>
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
    </div>
  );
};

export default StixObjectOrStixRelationship;
