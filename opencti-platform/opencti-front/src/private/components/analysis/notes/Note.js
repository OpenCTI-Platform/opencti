import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import ContainerHeader from '../../common/containers/ContainerHeader';
import NoteDetails from './NoteDetails';
import NoteEdition from './NoteEdition';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../external_references/StixCoreObjectExternalReferences';
import Security, { CollaborativeSecurity } from '../../../../utils/Security';
import {
  KNOWLEDGE_KNPARTICIPATE,
  KNOWLEDGE_KNUPDATE_KNDELETE,
} from '../../../../utils/hooks/useGranted';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import NotePopover from './NotePopover';
import ContainerStixObjectsOrStixRelationships from '../../common/containers/ContainerStixObjectsOrStixRelationships';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class NoteComponent extends Component {
  render() {
    const { classes, note } = this.props;
    return (
      <div className={classes.container}>
        <CollaborativeSecurity
          data={note}
          needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}
          placeholder={
            <ContainerHeader
              container={note}
              PopoverComponent={<NotePopover note={note} />}
            />
          }
        >
          <ContainerHeader
            container={note}
            PopoverComponent={<NotePopover note={note} />}
            popoverSecurity={[KNOWLEDGE_KNPARTICIPATE]}
          />
        </CollaborativeSecurity>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <NoteDetails note={note} />
          </Grid>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <StixDomainObjectOverview stixDomainObject={note} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        >
          <Grid item={true} xs={12}>
            <ContainerStixObjectsOrStixRelationships
              isSupportParticipation={true}
              container={note}
            />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        >
          <Grid item={true} xs={6}>
            <StixCoreObjectExternalReferences stixCoreObjectId={note.id} />
          </Grid>
          <Grid item={true} xs={6}>
            <StixCoreObjectLatestHistory stixCoreObjectId={note.id} />
          </Grid>
        </Grid>
        <Security needs={[KNOWLEDGE_KNPARTICIPATE]}>
          <NoteEdition noteId={note.id} />
        </Security>
      </div>
    );
  }
}

NoteComponent.propTypes = {
  note: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Note = createFragmentContainer(NoteComponent, {
  note: graphql`
    fragment Note_note on Note {
      id
      standard_id
      entity_type
      x_opencti_stix_ids
      spec_version
      revoked
      confidence
      created
      modified
      created_at
      updated_at
      createdBy {
        id
        name
        entity_type
      }
      creator {
        id
        name
      }
      objectMarking {
        edges {
          node {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
        }
      }
      objectLabel {
        edges {
          node {
            id
            value
            color
          }
        }
      }
      status {
        id
        order
        template {
          name
          color
        }
      }
      workflowEnabled
      ...NoteDetails_note
      ...ContainerHeader_container
      ...ContainerStixObjectsOrStixRelationships_container
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Note);
