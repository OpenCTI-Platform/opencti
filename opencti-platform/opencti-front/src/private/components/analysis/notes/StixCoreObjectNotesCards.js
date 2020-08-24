import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import { createPaginationContainer } from 'react-relay';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import StixCoreObjectNoteCard from './StixCoreObjectNoteCard';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import AddNotes from './AddNotes';

const styles = () => ({
  paper: {
    margin: 0,
    padding: '20px 20px 20px 20px',
    borderRadius: 6,
  },
});

class StixCoreObjectNotesCardsContainer extends Component {
  render() {
    const { t, stixCoreObjectId, data } = this.props;
    const notes = pathOr([], ['stixCoreObject', 'notes', 'edges'], data);
    return (
      <div style={{ height: '100%', marginTop: 40 }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Notes about this entity')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <AddNotes entityId={stixCoreObjectId} entityNotes={notes} />
        </Security>
        <div className="clearfix" />
        <Grid container={true} spacing={3}>
          {notes.map((noteEdge) => {
            const note = noteEdge.node;
            return (
              <Grid key={note.id} item={true} xs={4}>
                <StixCoreObjectNoteCard
                  node={note}
                  stixCoreObjectId={stixCoreObjectId}
                />
              </Grid>
            );
          })}
        </Grid>
      </div>
    );
  }
}

StixCoreObjectNotesCardsContainer.propTypes = {
  stixCoreObjectId: PropTypes.string,
  data: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixCoreObjectNotesCardsQuery = graphql`
  query StixCoreObjectNotesCardsQuery($count: Int!, $id: String) {
    ...StixCoreObjectNotesCards_data @arguments(count: $count, id: $id)
  }
`;

const StixCoreObjectNotesCards = createPaginationContainer(
  StixCoreObjectNotesCardsContainer,
  {
    data: graphql`
      fragment StixCoreObjectNotesCards_data on Query
        @argumentDefinitions(
          count: { type: "Int", defaultValue: 25 }
          id: { type: "String" }
        ) {
        stixCoreObject(id: $id) {
          id
          notes(first: $count) @connection(key: "Pagination_notes") {
            edges {
              node {
                id
                ...StixCoreObjectNoteCard_node
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
      return props.data && props.data.stixCoreObject.notes;
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
    query: stixCoreObjectNotesCardsQuery,
  },
);

export default compose(inject18n, withStyles(styles))(StixCoreObjectNotesCards);
