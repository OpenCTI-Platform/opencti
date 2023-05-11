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

class StixObjectOrStixRelationship extends Component {
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
          query={stixObjectOrStixRelationshipStixObjectOrStixRelationshipQuery}
          variables={{ id }}
          render={({ props }) => {
            if (props) {
              if (props.stixObjectOrStixRelationship) {
                let redirectLink;
                const { stixObjectOrStixRelationship } = props;
                const fromRestricted = stixObjectOrStixRelationship.from === null;
                const toRestricted = stixObjectOrStixRelationship.to === null;
                if (
                  stixObjectOrStixRelationship.relationship_type
                  === 'stix-sighting-relationship'
                ) {
                  redirectLink = !toRestricted
                    ? `${resolveLink(
                      stixObjectOrStixRelationship.to.entity_type,
                    )}/${
                      stixObjectOrStixRelationship.to.id
                    }/knowledge/sightings/${stixObjectOrStixRelationship.id}`
                    : undefined;
                } else if (stixObjectOrStixRelationship.relationship_type) {
                  if (stixObjectOrStixRelationship.from.relationship_type) {
                    redirectLink = !toRestricted
                      ? `${resolveLink(
                        stixObjectOrStixRelationship.to.entity_type,
                      )}/${
                        stixObjectOrStixRelationship.to.id
                      }/knowledge/relations/${stixObjectOrStixRelationship.id}`
                      : undefined;
                  } else {
                    redirectLink = !fromRestricted
                      ? `${resolveLink(
                        stixObjectOrStixRelationship.from.entity_type,
                      )}/${
                        stixObjectOrStixRelationship.from.id
                      }/knowledge/relations/${stixObjectOrStixRelationship.id}`
                      : undefined;
                  }
                } else {
                  redirectLink = `${resolveLink(
                    stixObjectOrStixRelationship.entity_type,
                  )}/${stixObjectOrStixRelationship.id}`;
                }
                if (redirectLink) {
                  return <Redirect exact from={`/id/${id}`} to={redirectLink}/>;
                }
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

StixObjectOrStixRelationship.propTypes = {
  match: PropTypes.object,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(StixObjectOrStixRelationship);
