import React, { FunctionComponent } from 'react';
import { graphql } from 'relay-runtime';
import useHelper from 'src/utils/hooks/useHelper';
import { Grid } from '@mui/material';
import { CollaborativeSecurity } from 'src/utils/Security';
import { KNOWLEDGE_KNUPDATE } from 'src/utils/hooks/useGranted';
import { useFragment } from 'react-relay';
import ContainerStixObjectsOrStixRelationships from '@components/common/containers/ContainerStixObjectsOrStixRelationships';
import StixCoreObjectLatestHistory from '@components/common/stix_core_objects/StixCoreObjectLatestHistory';
import StixDomainObjectOverview from '@components/common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../external_references/StixCoreObjectExternalReferences';
import NoteEdition from './NoteEdition';
import { Note_note$key } from './__generated__/Note_note.graphql';
import NoteDetails from './NoteDetails';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';

const NoteComponentFragment = graphql`
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
      x_opencti_reliability
    }
    creators {
      id
      name
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
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
`;

interface NoteComponentProps {
  noteFragment: Note_note$key
  enableReferences: boolean
}

const NoteComponent: FunctionComponent<NoteComponentProps> = ({
  noteFragment,
  enableReferences,
}) => {
  const note = useFragment(NoteComponentFragment, noteFragment);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const overviewLayoutCustomization = useOverviewLayoutCustomization(note.entity_type);

  return (<>
    <Grid
      container={true}
      spacing={3}
      style={{
        marginBottom: 20,
      }}
    >
      {
        overviewLayoutCustomization.map(({ key, width }) => {
          switch (key) {
            case 'details':
              return (
                <Grid key={key} item xs={width}>
                  <NoteDetails note={note} />
                </Grid>
              );
            case 'basicInformation':
              return (
                <Grid key={key} item xs={width}>
                  <StixDomainObjectOverview stixDomainObject={note} />
                </Grid>
              );
            case 'relatedEntities':
              return (
                <Grid key={key} item xs={width}>
                  <ContainerStixObjectsOrStixRelationships
                    isSupportParticipation={true}
                    container={note}
                    enableReferences={enableReferences}
                  />
                </Grid>
              );
            case 'externalReferences':
              return (
                <Grid key={key} item xs={width}>
                  <StixCoreObjectExternalReferences
                    stixCoreObjectId={note.id}
                  />
                </Grid>
              );
            case 'mostRecentHistory':
              return (
                <Grid key={key} item xs={width}>
                  <StixCoreObjectLatestHistory
                    stixCoreObjectId={note.id}
                  />
                </Grid>
              );
            default:
              return null;
          }
        })
      }
    </Grid>
    {!isFABReplaced && (
      <CollaborativeSecurity data={note} needs={[KNOWLEDGE_KNUPDATE]}>
        <NoteEdition noteId={note.id} />
      </CollaborativeSecurity>
    )}
  </>);
};

export default NoteComponent;
