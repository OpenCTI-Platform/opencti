import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import { createPaginationContainer } from 'react-relay';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import StixCoreObjectOrStixCoreRelationshipNoteCard from './StixCoreObjectOrStixCoreRelationshipNoteCard';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import AddNotes from './AddNotes';

const styles = () => ({
  paper: {
    margin: 0,
    padding: '20px 20px 20px 20px',
    borderRadius: 6,
  },
});

class StixSightingRelationshipNotesCardsContainer extends Component {
  render() {
    const {
      t, stixSightingRelationshipId, marginTop, data,
    } = this.props;
    const notes = pathOr(
      [],
      ['stixSightingRelationship', 'notes', 'edges'],
      data,
    );
    return (
      <div style={{ height: '100%', marginTop: marginTop || 40 }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Notes about this relationship')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <AddNotes
            stixCoreObjectOrStixCoreRelationshipId={stixSightingRelationshipId}
            stixCoreObjectOrStixCoreRelationshipNotes={notes}
          />
        </Security>
        <div className="clearfix" />
        <Grid
          container={true}
          spacing={3}
          style={{ transform: 'translateY(-15px)' }}
        >
          {notes.map((noteEdge) => {
            const note = noteEdge.node;
            return (
              <Grid key={note.id} item={true} xs={4}>
                <StixCoreObjectOrStixCoreRelationshipNoteCard
                  node={note}
                  stixCoreObjectOrStixSightingRelationshipId={
                    stixSightingRelationshipId
                  }
                />
              </Grid>
            );
          })}
        </Grid>
      </div>
    );
  }
}

StixSightingRelationshipNotesCardsContainer.propTypes = {
  stixSightingRelationshipId: PropTypes.string,
  marginTop: PropTypes.number,
  data: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixSightingRelationshipNotesCardsQuery = graphql`
  query StixSightingRelationshipNotesCardsQuery($count: Int!, $id: String!) {
    ...StixSightingRelationshipNotesCards_data
      @arguments(count: $count, id: $id)
  }
`;

const StixSightingRelationshipNotesCards = createPaginationContainer(
  StixSightingRelationshipNotesCardsContainer,
  {
    data: graphql`
      fragment StixSightingRelationshipNotesCards_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        id: { type: "String!" }
      ) {
        stixSightingRelationship(id: $id) {
          id
          notes(first: $count) @connection(key: "Pagination_notes") {
            edges {
              node {
                id
                ...StixCoreObjectOrStixCoreRelationshipNoteCard_node
              }
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.stixSightingRelationship.notes;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count }, fragmentVariables) {
      return {
        count,
        id: fragmentVariables.id,
      };
    },
    query: stixSightingRelationshipNotesCardsQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixSightingRelationshipNotesCards);
