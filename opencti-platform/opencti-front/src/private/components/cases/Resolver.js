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
      case_type
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
              if (caseEntity.case_type === 'feedback') {
                redirectLink = `/dashboard/cases/feedbacks/${caseEntity.id}`;
              } else if (caseEntity.case_type === 'incident') {
                redirectLink = `/dashboard/cases/incidents/${caseEntity.id}`;
              } else if (caseEntity.case_type === 'rfi') {
                redirectLink = `/dashboard/cases/rfis/${caseEntity.id}`;
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
