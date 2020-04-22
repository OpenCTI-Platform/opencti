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
import StixObjectNoteCard from './StixObjectNoteCard';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixObjectNotesCreation from './StixObjectNoteCreation';

const styles = () => ({
  paper: {
    margin: 0,
    padding: '20px 20px 20px 20px',
    borderRadius: 6,
  },
});

class StixObjectNotesComponent extends Component {
  render() {
    const {
      t, classes, entityId, inputType, data, marginTop,
    } = this.props;
    const notes = pathOr([], ['notes', 'edges'], data);
    return (
      <div style={{ height: '100%', marginTop: marginTop || 40 }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Notes about this entity')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixObjectNotesCreation
            entityId={entityId}
            onCreate={this.props.relay.refetch.bind(this)}
            inputType={inputType}
          />
        </Security>
        <div className="clearfix" />
        <Paper
          classes={{ root: classes.paper }}
          elevation={2}
          style={{ height: notes.length === 0 ? 200 : '100%' }}
        >
          {notes.length > 0 ? (
            <Grid container={true} spacing={3}>
              {notes.map((noteEdge) => {
                const note = noteEdge.node;
                return (
                  <Grid key={note.id} item={true} xs={3}>
                    <StixObjectNoteCard
                      node={note}
                      onUpdate={this.props.relay.refetch.bind(this)}
                    />
                  </Grid>
                );
              })}
            </Grid>
          ) : (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                {t('No notes about this entity yet.')}
              </span>
            </div>
          )}
        </Paper>
      </div>
    );
  }
}

StixObjectNotesComponent.propTypes = {
  entityId: PropTypes.string,
  inputType: PropTypes.string,
  marginTop: PropTypes.number,
  data: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixObjectNotesCardsQuery = graphql`
  query StixObjectNotesCardsQuery(
    $first: Int
    $orderBy: NotesOrdering
    $orderMode: OrderingMode
    $filters: [NotesFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    ...StixObjectNotesCards_data
  }
`;

const StixObjectNotesCards = createRefetchContainer(
  StixObjectNotesComponent,
  {
    data: graphql`
      fragment StixObjectNotesCards_data on Query {
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
              ...StixObjectNoteCard_node
            }
          }
        }
      }
    `,
  },
  stixObjectNotesCardsQuery,
);

export default compose(inject18n, withStyles(styles))(StixObjectNotesCards);
