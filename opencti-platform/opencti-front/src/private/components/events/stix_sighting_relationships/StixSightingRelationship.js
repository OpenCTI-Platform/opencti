import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixSightingRelationshipOverview from './StixSightingRelationshipOverview';
import Loader from '../../../../components/Loader';

const styles = () => ({
  container: {
    margin: 0,
  },
});

const stixSightingRelationshipQuery = graphql`
  query StixSightingRelationshipQuery($id: String!) {
    stixSightingRelationship(id: $id) {
      ...StixSightingRelationshipOverview_stixSightingRelationship
    }
  }
`;

class StixSightingRelationship extends Component {
  render() {
    const {
      classes,
      entityId,
      paddingRight,
      match: {
        params: { sightingId },
      },
    } = this.props;
    return (
      <div className={classes.container}>
        <QueryRenderer
          query={stixSightingRelationshipQuery}
          variables={{ id: sightingId }}
          render={({ props }) => {
            if (props && props.stixSightingRelationship) {
              return (
                <StixSightingRelationshipOverview
                  entityId={entityId}
                  stixSightingRelationship={props.stixSightingRelationship}
                  paddingRight={paddingRight}
                />
              );
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

StixSightingRelationship.propTypes = {
  entityId: PropTypes.string,
  paddingRight: PropTypes.bool,
  classes: PropTypes.object,
  t: PropTypes.func,
  match: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(StixSightingRelationship);
