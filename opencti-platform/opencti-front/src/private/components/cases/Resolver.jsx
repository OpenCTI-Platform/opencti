import React from 'react';
import { Redirect, useParams } from 'react-router-dom';
import { graphql } from 'react-relay';
import { makeStyles } from '@mui/styles';
import { QueryRenderer } from '../../../relay/environment';
import Loader from '../../../components/Loader';
import ErrorNotFound from '../../../components/ErrorNotFound';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: 0,
  },
}));

export const resolverCaseQuery = graphql`
  query ResolverCaseQuery($id: String!) {
    container(id: $id) {
      id
      entity_type
      ... on CaseTask {
        objects {
          edges {
            node {
              ... on Case {
                entity_type
                id
              }
            }
          }
        }
      }
    }
  }
`;

const resolvePathRecursively = (caseEntity) => {
  let url = '';
  switch (caseEntity.entity_type) {
    case 'Case-Task':
      if (caseEntity.objects?.edges?.at(0)?.node) {
        url = resolvePathRecursively(caseEntity.objects.edges.at(0).node);
      }
      break;
    case 'Feedback':
      url = `/dashboard/cases/feedbacks/${caseEntity.id}`;
      break;
    case 'Case-Incident':
      url = `/dashboard/cases/incidents/${caseEntity.id}`;
      break;
    case 'Case-Rfi':
      url = `/dashboard/cases/rfis/${caseEntity.id}`;
      break;
    case 'Case-Rft':
      url = `/dashboard/cases/rfts/${caseEntity.id}`;
      break;
    default:
      break;
  }
  return url;
};

const Resolver = () => {
  const classes = useStyles();
  const { caseId } = useParams();
  return (
    <div className={classes.container}>
      <QueryRenderer
        query={resolverCaseQuery}
        variables={{ id: caseId }}
        render={({ props }) => {
          if (props) {
            if (props.container) {
              const { container: caseEntity } = props;
              const redirectLink = resolvePathRecursively(caseEntity);
              if (!redirectLink) {
                return <ErrorNotFound />;
              }
              return (
                <Redirect
                  exact
                  from={`/dashboard/cases/resolver/${caseId}`}
                  to={redirectLink}
                />
              );
            }
            return <ErrorNotFound />;
          }
          return <Loader />;
        }}
      />
    </div>
  );
};

export default Resolver;
