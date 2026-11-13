import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import { styled } from '@mui/material/styles';
import withRouter from '../../../../utils/compat_router/withRouter';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreRelationshipOverview from './StixCoreRelationshipOverview';
import Loader from '../../../../components/Loader';

const Container = styled('div')({
  margin: 0,
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
      params: { relationId },
    } = this.props;
    return (
      <Container>
        <QueryRenderer
          query={stixCoreRelationshipQuery}
          variables={{ id: relationId }}
          render={({ props }) => {
            if (props && props.stixCoreRelationship) {
              return (
                <StixCoreRelationshipOverview
                  data={props.stixCoreRelationship}
                />
              );
            }
            return <Loader />;
          }}
        />
      </Container>
    );
  }
}

StixCoreRelationship.propTypes = {
  entityId: PropTypes.string,
  paddingRight: PropTypes.bool,
  t: PropTypes.func,
  match: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
)(StixCoreRelationship);
