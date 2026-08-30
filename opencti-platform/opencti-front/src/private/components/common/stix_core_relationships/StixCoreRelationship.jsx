import React from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import { useParams } from 'react-router-dom';
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

const StixCoreRelationship = (props) => {
  const { classes, entityId, paddingRight } = props;
  const { relationId } = useParams();
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
};

StixCoreRelationship.propTypes = {
  entityId: PropTypes.string,
  paddingRight: PropTypes.bool,
  classes: PropTypes.object,
};

export default withStyles(styles)(StixCoreRelationship);
