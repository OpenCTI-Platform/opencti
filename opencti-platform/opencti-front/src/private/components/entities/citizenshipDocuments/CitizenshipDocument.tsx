import { graphql } from 'relay-runtime';
import React from 'react';
import { useFragment } from 'react-relay';
import { Grid } from '@mui/material';
import { useInitCreateRelationshipContext } from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import { CitizenshipDocument_citizenshipDocument$key } from './__generated__/CitizenshipDocument_citizenshipDocument.graphql';
import CitizenshipDocumentDetails from './CitizenshipDocumentDetails';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';

const citizenshipDocumentFragment = graphql`
  fragment CitizenshipDocument_citizenshipDocument on CitizenshipDocument {
    id
    standard_id
    entity_type
    x_opencti_stix_ids
    x_opencti_citizenship_document_type
    x_opencti_citizenship_document_id
    x_opencti_firstname
    x_opencti_lastname
    spec_version
    revoked
    x_opencti_reliability
    confidence
    created
    modified
    created_at
    updated_at
    isUser
    createdBy {
      ... on Identity {
        id
        name
        entity_type
        x_opencti_reliability
      }
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
    name
    x_opencti_aliases
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    ...CitizenshipDocumentDetails_citizenshipDocument
  }
`;

interface CitizenshipDocumentProps {
  citizenshipDocumentData: CitizenshipDocument_citizenshipDocument$key;
  viewAs: string;
}

const CitizenshipDocument: React.FC<CitizenshipDocumentProps> = ({
  citizenshipDocumentData,
  viewAs,
}) => {
  useInitCreateRelationshipContext();

  const citizenshipDocument = useFragment<CitizenshipDocument_citizenshipDocument$key>(
    citizenshipDocumentFragment,
    citizenshipDocumentData,
  );
  const lastReportsProps = viewAs === 'knowledge'
    ? { stixCoreObjectOrStixRelationshipId: citizenshipDocument.id }
    : { authorId: citizenshipDocument.id };
  return (
    <div data-testid="citizenship-document-details-page">
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20 }}
      >
        <Grid item xs={6}>
          <CitizenshipDocumentDetails citizenshipDocument={citizenshipDocument} />
        </Grid>
        <Grid item xs={6}>
          <StixDomainObjectOverview
            stixDomainObject={citizenshipDocument}
          />
        </Grid>
        {viewAs === 'knowledge' && (
          <Grid item xs={6}>
            <SimpleStixObjectOrStixRelationshipStixCoreRelationships
              stixObjectOrStixRelationshipId={citizenshipDocument.id}
              stixObjectOrStixRelationshipLink={`/dashboard/entities/citizenship_documents/${citizenshipDocument.id}/knowledge`}
            />
          </Grid>
        )}
        <Grid
          item
          xs={viewAs === 'knowledge' ? 6 : 12}
        >
          <StixCoreObjectOrStixRelationshipLastContainers
            {...lastReportsProps}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectExternalReferences
            stixCoreObjectId={citizenshipDocument.id}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectLatestHistory stixCoreObjectId={citizenshipDocument.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={citizenshipDocument.id}
        defaultMarkings={citizenshipDocument.objectMarking ?? []}
      />
    </div>
  );
};

export default CitizenshipDocument;
