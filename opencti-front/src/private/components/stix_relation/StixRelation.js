import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import StixRelationOverview from './StixRelationOverview';

const styles = () => ({
  container: {
    margin: 0,
  },
});

const stixRelationQuery = graphql`
    query StixRelationQuery($id: String!) {
        stixRelation(id: $id) {
            ...StixRelationOverview_stixRelation
        }
    }
`;

class StixRelation extends Component {
  render() {
    const {
      classes, entityId, inversedRelations, match: { params: { relationId } },
    } = this.props;
    return (
      <div className={classes.container}>
        <QueryRenderer
          query={stixRelationQuery}
          variables={{ id: relationId }}
          render={({ props }) => {
            if (props) { // Done
              return (
                <StixRelationOverview entityId={entityId} stixRelation={props.stixRelation} inversedRelations={inversedRelations}/>
              );
            }
            // Loading
            return <div> &nbsp; </div>;
          }}
        />
      </div>
    );
  }
}

StixRelation.propTypes = {
  entityId: PropTypes.string,
  inversedRelations: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
  match: PropTypes.object,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixRelation);
