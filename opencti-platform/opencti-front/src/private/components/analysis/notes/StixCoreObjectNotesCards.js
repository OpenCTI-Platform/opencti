import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import { createRefetchContainer } from 'react-relay';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper/Paper';
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

class StixCoreObjectNotesComponent extends Component {
  render() {
    const {
      t, classes, entityId, data, marginTop,
    } = this.props;
    const notes = pathOr([], ['notes', 'edges'], data);
    return (
      <div style={{ height: '100%', marginTop: marginTop || 40 }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Notes about this entity')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <AddNotes entityId={entityId} entityNotes={notes} />
        </Security>
        <div className="clearfix" />
        <Grid container={true} spacing={3}>
          {notes.map((noteEdge) => {
            const note = noteEdge.node;
            return (
              <Grid key={note.id} item={true} xs={4}>
                <StixCoreObjectNoteCard
                  node={note}
                  onUpdate={this.props.relay.refetch.bind(this)}
                />
              </Grid>
            );
          })}
        </Grid>
      </div>
    );
  }
}

StixCoreObjectNotesComponent.propTypes = {
  entityId: PropTypes.string,
  marginTop: PropTypes.number,
  data: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixCoreObjectNotesCardsQuery = graphql`
  query StixCoreObjectNotesCardsQuery(
    $first: Int
    $orderBy: NotesOrdering
    $orderMode: OrderingMode
    $filters: [NotesFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    ...StixCoreObjectNotesCards_data
  }
`;

const StixCoreObjectNotesCards = createRefetchContainer(
  StixCoreObjectNotesComponent,
  {
    data: graphql`
      fragment StixCoreObjectNotesCards_data on Query {
        notes(
          first: $first
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
          filterMode: $filterMode
          search: $search
        ) {
          edges {
            node {
              ...StixCoreObjectNoteCard_node
            }
          }
        }
      }
    `,
  },
  stixCoreObjectNotesCardsQuery,
);

export default compose(inject18n, withStyles(styles))(StixCoreObjectNotesCards);
