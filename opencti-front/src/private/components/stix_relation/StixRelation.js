import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Fab from '@material-ui/core/Fab';
import { Edit } from '@material-ui/icons';
import inject18n from '../../../components/i18n';
import { commitMutation, QueryRenderer, WS_ACTIVATED } from '../../../relay/environment';
import StixRelationOverview from './StixRelationOverview';
import StixRelationEdition, { stixRelationEditionDeleteMutation } from './StixRelationEdition';
import { stixRelationEditionFocus } from './StixRelationEditionOverview';

const styles = () => ({
  container: {
    margin: 0,
  },
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 300,
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
  constructor(props) {
    super(props);
    this.state = { openEdit: false };
  }

  handleOpenEdition() {
    this.setState({ openEdit: true });
  }

  handleCloseEdition() {
    const { match: { params: { relationId } } } = this.props;
    if (WS_ACTIVATED) {
      commitMutation({
        mutation: stixRelationEditionFocus,
        variables: {
          id: relationId,
          input: { focusOn: '' },
        },
      });
    }
    this.setState({ openEdit: false });
  }

  handleDelete() {
    const { location, match: { params: { relationId } } } = this.props;
    commitMutation({
      mutation: stixRelationEditionDeleteMutation,
      variables: {
        id: relationId,
      },
      onCompleted: () => {
        this.handleCloseEdition();
        this.props.history.push(location.pathname.replace(`/relations/${relationId}`, ''));
      },
    });
  }

  render() {
    const {
      classes, entityId, inversedRelations, match: { params: { relationId } },
    } = this.props;
    return (
      <div className={classes.container}>
        <Fab onClick={this.handleOpenEdition.bind(this)}
             color='secondary' aria-label='Edit'
             className={classes.editButton}><Edit/></Fab>
        <QueryRenderer
          query={stixRelationQuery}
          variables={{ id: relationId }}
          render={({ props }) => {
            if (props && props.stixRelation) {
              return <StixRelationOverview
                entityId={entityId}
                stixRelation={props.stixRelation}
                inversedRelations={inversedRelations}
              />;
            }
            return <div> &nbsp; </div>;
          }}
        />
        <StixRelationEdition
          open={this.state.openEdit}
          stixRelationId={relationId}
          handleClose={this.handleCloseEdition.bind(this)}
          handleDelete={this.handleDelete.bind(this)}
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
  location: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),

)(StixRelation);
