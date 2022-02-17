/* eslint-disable import/no-cycle */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import Paper from '@material-ui/core/Paper';
import { withStyles } from '@material-ui/core/styles';
import { createFragmentContainer, createPaginationContainer } from 'react-relay';
import Typography from '@material-ui/core/Typography';
import { ConnectionHandler } from 'relay-runtime';
import inject18n from '../../../../components/i18n';
import CyioCoreObjectOrCyioCoreRelationshipNoteCard from './CyioCoreObjectOrCyioCoreRelationshipNoteCard';
// import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import { commitMutation } from '../../../../relay/environment';
import { noteCreationMutation } from './NoteCreation';
import CyioNoteCreation from './CyioNoteCreation';

const styles = (theme) => ({
  paper: {
    margin: 0,
    padding: '20px 20px 20px 20px',
    borderRadius: 6,
  },
  heading: {
    display: 'flex',
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  createButton: {
    float: 'left',
    margin: '-15px 0 0 0px',
  },
});

// const noteValidation = (t) => Yup.object().shape({
//   attribute_abstract: Yup.string(),
//   content: Yup.string().required(t('This field is required')),
// });

const sharedUpdater = (store, entityId, newEdge) => {
  const entity = store.get(entityId);
  const conn = ConnectionHandler.getConnection(entity, 'Pagination_notes');
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class CyioCoreObjectNotesCardsContainer extends Component {
  constructor(props) {
    super(props);
    this.bottomRef = React.createRef();
    this.state = { open: false, search: '' };
  }

  scrollToBottom() {
    setTimeout(() => {
      this.bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }, 400);
  }

  handleToggleWrite() {
    const expanded = !this.state.open;
    this.setState({ open: expanded }, () => {
      if (expanded) {
        this.scrollToBottom();
      }
    });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const { cyioCoreObjectId, data } = this.props;
    const defaultMarking = R.pathOr(
      [],
      ['stixCoreObject', 'objectMarking', 'edges'],
      data,
    ).map((n) => n.node.id);
    const adaptedValues = R.pipe(
      R.assoc('objectMarking', [
        ...defaultMarking,
        ...R.pluck('value', values.objectMarking),
      ]),
      R.assoc('objects', [cyioCoreObjectId]),
      R.assoc('createdBy', R.pathOr(null, ['createdBy', 'value'], values)),
      R.assoc('objectLabel', R.pluck('value', values.objectLabel)),
    )(values);
    commitMutation({
      mutation: noteCreationMutation,
      variables: {
        input: adaptedValues,
      },
      setSubmitting,
      updater: (store) => {
        const payload = store.getRootField('noteAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node');
        sharedUpdater(store, cyioCoreObjectId, newEdge);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  }

  onReset() {
    this.handleToggleWrite();
  }

  render() {
    const {
      t, cyioCoreObjectId, marginTop, data, height,
    } = this.props;
    // const notes = R.pathOr([], ['cyioNotes', 'edges'], data);
    const paginationOptions = {
      search: this.state.search,
    };
    return (
      <div style={{ marginTop: marginTop || 40 }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Notes')}
        </Typography>
        {/* <Security needs={[KNOWLEDGE_KNUPDATE]}> */}
        <CyioNoteCreation
          display={true}
          contextual={true}
          inputValue={this.state.search}
          paginationOptions={paginationOptions}
        />
        {/* </Security> */}
        <div className="clearfix" />
        {
          data ? (
            <Paper style={{ height: '100%', paddingTop: '15px' }} >
              {data.map((note) => (
                <CyioCoreObjectOrCyioCoreRelationshipNoteCard
                  key={note.id}
                  node={note}
                  cyioCoreObjectOrCyioCoreRelationshipId={cyioCoreObjectId}
                />
              ))}
            </Paper>
          ) : (
            <Paper style={{ minHeight: height || 100, height: height || 100 }} />
          )
        }
        {/* <div style={{ marginTop: 100 }} /> */}
        <div ref={this.bottomRef} />
      </div>
    );
  }
}

CyioCoreObjectNotesCardsContainer.propTypes = {
  cyioCoreObjectId: PropTypes.string,
  marginTop: PropTypes.number,
  height: PropTypes.number,
  data: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(CyioCoreObjectNotesCardsContainer);
