import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Redirect, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { graphql } from 'react-relay';
import inject18n from '../../components/i18n';
import { QueryRenderer } from '../../relay/environment';
import { resolveLink } from '../../utils/Entity';
import Loader from '../../components/Loader';
import ErrorNotFound from '../../components/ErrorNotFound';

const styles = () => ({
  container: {
    margin: 0,
    padding: 0,
  },
});

export const stixCoreObjectOrStixCoreRelationshipStixObjectOrStixRelationshipQuery = graphql`
  query StixCoreObjectOrStixCoreRelationshipStixObjectOrStixRelationshipQuery(
    $id: String!
  ) {
    stixObjectOrStixRelationship(id: $id) {
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

class StixCoreObjectOrStixCoreRelationship extends Component {
  render() {
    const {
      classes,
      match: {
        params: { id },
      },
    } = this.props;

    return (
      <div className={classes.container}>
        <QueryRenderer
          query={
            stixCoreObjectOrStixCoreRelationshipStixObjectOrStixRelationshipQuery
          }
          variables={{ id }}
          render={({ props }) => {
            if (props) {
              if (props.stixObjectOrStixRelationship) {
                let redirectLink;
                const { stixObjectOrStixRelationship } = props;
                if (stixObjectOrStixRelationship.relationship_type) {
                  if (stixObjectOrStixRelationship.from.relationship_type) {
                    redirectLink = `${resolveLink(
                      stixObjectOrStixRelationship.to.entity_type,
                    )}/${
                      stixObjectOrStixRelationship.to.id
                    }/knowledge/relations/${stixObjectOrStixRelationship.id}`;
                  } else {
                    redirectLink = `${resolveLink(
                      stixObjectOrStixRelationship.from.entity_type,
                    )}/${
                      stixObjectOrStixRelationship.from.id
                    }/knowledge/relations/${stixObjectOrStixRelationship.id}`;
                  }
                } else {
                  redirectLink = `${resolveLink(
                    stixObjectOrStixRelationship.entity_type,
                  )}/${stixObjectOrStixRelationship.id}`;
                }
                return <Redirect exact from={`/id/${id}`} to={redirectLink} />;
              }
              return <ErrorNotFound />;
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

StixCoreObjectOrStixCoreRelationship.propTypes = {
  match: PropTypes.object,
  history: PropTypes.object,
  me: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(StixCoreObjectOrStixCoreRelationship);
