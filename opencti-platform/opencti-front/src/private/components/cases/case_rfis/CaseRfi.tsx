import Grid from '@mui/material/Grid';
import React from 'react';
import { useFragment } from 'react-relay';
import { convertMarkings } from '../../../../utils/edition';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import ContainerStixObjectsOrStixRelationships from '../../common/containers/ContainerStixObjectsOrStixRelationships';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import { CaseUtils_case$key } from '../__generated__/CaseUtils_case.graphql';
import CaseTasksLines from '../tasks/CaseTasksLines';
import { caseFragment } from '../CaseUtils';
import CaseRfiDetails from './CaseRfiDetails';
import CaseRfiEdition from './CaseRfiEdition';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';

interface CaseRfiProps {
  caseRfiData: CaseUtils_case$key;
  enableReferences: boolean;
}

const CaseRfi: React.FC<CaseRfiProps> = ({ caseRfiData, enableReferences }) => {
  const { t_i18n } = useFormatter();
  const caseRfi = useFragment(caseFragment, caseRfiData);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const overviewLayoutCustomization = useOverviewLayoutCustomization(caseRfi.entity_type);

  return (
    <>
      <Grid
        container
        spacing={3}
        style={{ marginBottom: 20 }}
      >
        {
          overviewLayoutCustomization.map(({ key, width }) => {
            switch (key) {
              case 'details':
                return (
                  <Grid key={key} item xs={width}>
                    <CaseRfiDetails caseRfiData={caseRfi} />
                  </Grid>
                );
              case 'basicInformation':
                return (
                  <Grid key={key} item xs={width}>
                    <StixDomainObjectOverview
                      stixDomainObject={caseRfi}
                      displayAssignees
                      displayParticipants
                    />
                  </Grid>
                );
              case 'task':
                return (
                  <Grid key={key} item xs={width}>
                    <CaseTasksLines
                      caseId={caseRfi.id}
                      defaultMarkings={convertMarkings(caseRfi)}
                      enableReferences={enableReferences}
                    />
                  </Grid>
                );
              case 'originOfTheCase':
                return (
                  <Grid key={key} item xs={width}>
                    <ContainerStixObjectsOrStixRelationships
                      isSupportParticipation={false}
                      container={caseRfi}
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
                      container={caseRfi}
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
                      container={caseRfi}
                      enableReferences={enableReferences}
                    />
                  </Grid>
                );
              case 'externalReferences':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectExternalReferences
                      stixCoreObjectId={caseRfi.id}
                    />
                  </Grid>
                );
              case 'mostRecentHistory':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectLatestHistory
                      stixCoreObjectId={caseRfi.id}
                    />
                  </Grid>
                );
              case 'notes':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectOrStixCoreRelationshipNotes
                      stixCoreObjectOrStixCoreRelationshipId={caseRfi.id}
                      defaultMarkings={caseRfi.objectMarking ?? []}
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
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <CaseRfiEdition caseId={caseRfi.id} />
        </Security>
      )}
    </>
  );
};

export default CaseRfi;
