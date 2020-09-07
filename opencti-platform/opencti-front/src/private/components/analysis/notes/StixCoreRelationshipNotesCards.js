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

class StixCoreRelationshipNotesCardsContainer extends Component {
  render() {
    const {
      t, stixCoreRelationshipId, marginTop, data,
    } = this.props;
    const notes = pathOr([], ['stixCoreRelationship', 'notes', 'edges'], data);
    return (
      <div style={{ height: '100%', marginTop: marginTop || 40 }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Notes about this relationship')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <AddNotes
            stixCoreObjectOrStixCoreRelationshipId={stixCoreRelationshipId}
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
                  stixCoreObjectOrStixCoreRelationshipId={
                    stixCoreRelationshipId
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

StixCoreRelationshipNotesCardsContainer.propTypes = {
  stixCoreRelationshipId: PropTypes.string,
  marginTop: PropTypes.number,
  data: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixCoreRelationshipNotesCardsQuery = graphql`
  query StixCoreRelationshipNotesCardsQuery($count: Int!, $id: String!) {
    ...StixCoreRelationshipNotesCards_data @arguments(count: $count, id: $id)
  }
`;

const StixCoreRelationshipNotesCards = createPaginationContainer(
  StixCoreRelationshipNotesCardsContainer,
  {
    data: graphql`
      fragment StixCoreRelationshipNotesCards_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        id: { type: "String!" }
      ) {
        stixCoreRelationship(id: $id) {
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
      return props.data && props.data.stixCoreRelationshipObject.notes;
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
    query: stixCoreRelationshipNotesCardsQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipNotesCards);
