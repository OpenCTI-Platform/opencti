import Grid from '@mui/material/Grid';
import React from 'react';
import { useFragment } from 'react-relay';
import { CaseUtils_case$key } from '@components/cases/__generated__/CaseUtils_case.graphql';
import { useFormatter } from '../../../../components/i18n';
import { convertMarkings } from '../../../../utils/edition';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import ContainerStixObjectsOrStixRelationships from '../../common/containers/ContainerStixObjectsOrStixRelationships';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import CaseTasksLines from '../tasks/CaseTasksLines';
import { caseFragment } from '../CaseUtils';
import CaseIncidentDetails from './CaseIncidentDetails';
import CaseIncidentEdition from './CaseIncidentEdition';
import useHelper from '../../../../utils/hooks/useHelper';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';

interface CaseIncidentProps {
  caseIncidentData: CaseUtils_case$key;
  enableReferences: boolean;
}

const CaseIncident: React.FC<CaseIncidentProps> = ({ caseIncidentData, enableReferences }) => {
  const { t_i18n } = useFormatter();
  const caseIncident = useFragment(caseFragment, caseIncidentData);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const { canEdit } = useGetCurrentUserAccessRight(caseIncident.currentUserAccessRight);

  const caseIncidentResponseOverviewLayoutCustomization = useOverviewLayoutCustomization(caseIncident.entity_type);

  return (
    <>
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20 }}
      >
        {
          caseIncidentResponseOverviewLayoutCustomization.map(({ key, width }) => {
            switch (key) {
              case 'details':
                return (
                  <Grid key={key} item xs={width}>
                    <CaseIncidentDetails caseIncidentData={caseIncident} />
                  </Grid>
                );
              case 'basicInformation':
                return (
                  <Grid key={key} item xs={width}>
                    <StixDomainObjectOverview
                      stixDomainObject={caseIncident}
                      displayAssignees
                      displayParticipants
                    />
                  </Grid>
                );
              case 'task':
                return (
                  <Grid key={key} item xs={width}>
                    <CaseTasksLines
                      caseId={caseIncident.id}
                      defaultMarkings={convertMarkings(caseIncident)}
                      enableReferences={enableReferences}
                    />
                  </Grid>
                );
              case 'originOfTheCase':
                return (
                  <Grid key={key} item xs={width}>
                    <ContainerStixObjectsOrStixRelationships
                      isSupportParticipation={false}
                      container={caseIncident}
                      types={['Incident', 'stix-sighting-relationship', 'Report']}
                      title={t_i18n('Origin of the case')}
                      enableReferences={enableReferences}
                    />
                  </Grid>
                );
              case 'observables':
                return (
                  <Grid key={key} item xs={width}>
                    <ContainerStixObjectsOrStixRelationships
                      isSupportParticipation={false}
                      container={caseIncident}
                      types={['Stix-Cyber-Observable']}
                      title={t_i18n('Observables')}
                      enableReferences={enableReferences}
                    />
                  </Grid>
                );
              case 'relatedEntities':
                return (
                  <Grid key={key} item xs={width}>
                    <ContainerStixObjectsOrStixRelationships
                      isSupportParticipation={false}
                      container={caseIncident}
                      types={[
                        'Threat-Actor',
                        'Intrusion-Set',
                        'Campaign',
                        'Malware',
                        'Tool',
                        'Attack-Pattern',
                        'Identity',
                        'Location',
                      ]}
                      title={t_i18n('Other entities')}
                      enableReferences={enableReferences}
                    />
                  </Grid>
                );
              case 'externalReferences':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectExternalReferences
                      stixCoreObjectId={caseIncident.id}
                    />
                  </Grid>
                );
              case 'mostRecentHistory':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectLatestHistory
                      stixCoreObjectId={caseIncident.id}
                    />
                  </Grid>
                );
              case 'notes':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectOrStixCoreRelationshipNotes
                      stixCoreObjectOrStixCoreRelationshipId={caseIncident.id}
                      defaultMarkings={caseIncident.objectMarking ?? []}
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
        <Security needs={[KNOWLEDGE_KNUPDATE]} hasAccess={canEdit}>
          <CaseIncidentEdition caseId={caseIncident.id} />
        </Security>
      )}
    </>
  );
};

export default CaseIncident;
