import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import ContainerHeader from '../../common/containers/ContainerHeader';
import NoteDetails from './NoteDetails';
import NoteEdition from './NoteEdition';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../external_references/StixCoreObjectExternalReferences';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
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
        <ContainerHeader container={note} PopoverComponent={<NotePopover />} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <StixDomainObjectOverview stixDomainObject={note} />
          </Grid>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <ContainerStixObjectsOrStixRelationships container={note} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        >
          <Grid item={true} xs={12}>
            <NoteDetails note={note} />
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
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
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
      x_opencti_stix_ids
      spec_version
      revoked
      confidence
      created
      modified
      created_at
      updated_at
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      creator {
        id
        name
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
