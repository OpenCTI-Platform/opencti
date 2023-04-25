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
    case(id: $id) {
      id
    }
  }
`;

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
            if (props.case) {
              let redirectLink;
              const { case: caseEntity } = props;
              if (caseEntity.entity_type === 'Feedback') {
                redirectLink = `/dashboard/cases/feedbacks/${caseEntity.id}`;
              } else if (caseEntity.entity_type === 'Case-Incident') {
                redirectLink = `/dashboard/cases/incidents/${caseEntity.id}`;
              } else if (caseEntity.entity_type === 'Case-Rfi') {
                redirectLink = `/dashboard/cases/rfis/${caseEntity.id}`;
              } else if (caseEntity.entity_type === 'Case-Rft') {
                redirectLink = `/dashboard/cases/rfts/${caseEntity.id}`;
              } else {
                redirectLink = `/dashboard/cases/others/${caseEntity.id}`;
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
