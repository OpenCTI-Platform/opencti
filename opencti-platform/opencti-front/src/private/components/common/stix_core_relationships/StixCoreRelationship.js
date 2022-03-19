import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreRelationshipOverview from './StixCoreRelationshipOverview';
import Loader from '../../../../components/Loader';

const styles = () => ({
  container: {
    margin: 0,
  },
});

const stixCoreRelationshipQuery = graphql`
  query StixCoreRelationshipQuery($id: String!) {
    stixCoreRelationship(id: $id) {
      ...StixCoreRelationshipOverview_stixCoreRelationship
    }
  }
`;

class StixCoreRelationship extends Component {
  render() {
    const {
      classes,
      entityId,
      paddingRight,
      match: {
        params: { relationId },
      },
    } = this.props;
    return (
      <div className={classes.container}>
        <QueryRenderer
          query={stixCoreRelationshipQuery}
          variables={{ id: relationId }}
          render={({ props }) => {
            if (props && props.stixCoreRelationship) {
              return (
                <StixCoreRelationshipOverview
                  entityId={entityId}
                  stixCoreRelationship={props.stixCoreRelationship}
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

StixCoreRelationship.propTypes = {
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
)(StixCoreRelationship);
