/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { Redirect } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../../components/i18n';
import EntityNoteDetails from './EntityNoteDetails';
import EntitiesNotesPopover from './EntitiesNotesPopover';
import EntitiesNotesDeletion from './EntitiesNotesDeletion';
import CyioDomainObjectHeader from '../../../common/stix_domain_objects/CyioDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../../utils/Security';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import NoteEntityEditionContainer from './NoteEntityEditionContainer';
import EntitiesNotesCreation from './EntitiesNotesCreation';
import RelatedTasks from '../../../riskAssessment/risks/remediations/RelatedTasks';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class EntityNoteComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayEdit: false,
      openDataCreation: false,
    };
  }

  handleDisplayEdit() {
    this.setState({ displayEdit: !this.state.displayEdit });
  }

  handleOpenNewCreation() {
    this.setState({ openDataCreation: !this.state.openDataCreation });
  }

  render() {
    const {
      note,
      classes,
      history,
      location,
      refreshQuery,
    } = this.props;
    const { me } = this.props.me;
    return (
      <>
        <div className={classes.container}>
          <CyioDomainObjectHeader
            name={note.abstract}
            history={history}
            cyioDomainObject={note}
            goBack='/data/entities/notes'
            PopoverComponent={<EntitiesNotesPopover />}
            OperationsComponent={<EntitiesNotesDeletion />}
            handleDisplayEdit={this.handleDisplayEdit.bind(this)}
            handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
          />
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
          >
            <Grid item={true} xs={12}>
              <EntityNoteDetails note={note} history={history} refreshQuery={refreshQuery} />
            </Grid>
          </Grid>
        </div>
        <EntitiesNotesCreation
          openDataCreation={this.state.openDataCreation}
          handleNoteCreation={this.handleOpenNewCreation.bind(this)}
          history={history}
          me={me}
        />
        <NoteEntityEditionContainer
          displayEdit={this.state.displayEdit}
          history={history}
          refreshQuery={refreshQuery}
          note={note}
          handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        />
      </>
    );
  }
}

EntityNoteComponent.propTypes = {
  note: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  refreshQuery: PropTypes.func,
};

const EntityNote = createFragmentContainer(EntityNoteComponent, {
  note: graphql`
    fragment EntityNote_note on CyioNote {
      __typename
      id
      content
      created
      authors
      abstract
      modified
      labels {
        __typename
        id
        name
        color
        entity_type
        description
      }
      ...EntityNoteDetails_note
    }
  `,
});

export default compose(inject18n, withStyles(styles))(EntityNote);
