import Grid from '@mui/material/Grid';
import React, { useRef } from 'react';
import { useFragment } from 'react-relay';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import { CaseUtils_case$key } from '@components/cases/__generated__/CaseUtils_case.graphql';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import { convertMarkings } from '../../../../utils/edition';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import ContainerStixObjectsOrStixRelationships from '../../common/containers/ContainerStixObjectsOrStixRelationships';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import { CaseTasksLinesQuery, CaseTasksLinesQuery$variables } from '../tasks/__generated__/CaseTasksLinesQuery.graphql';
import CaseTasksLines, { caseTasksLinesQuery } from '../tasks/CaseTasksLines';
import { caseFragment } from '../CaseUtils';
import CaseIncidentDetails from './CaseIncidentDetails';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { tasksDataColumns } from '../tasks/TasksLine';
import ListLines from '../../../../components/list_lines/ListLines';
import { CaseTasksLineDummy } from '../tasks/CaseTasksLine';
import { isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';

interface CaseIncidentProps {
  caseIncidentData: CaseUtils_case$key;
  enableReferences: boolean;
}

const CaseIncident: React.FC<CaseIncidentProps> = ({ caseIncidentData, enableReferences }) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const ref = useRef(null);
  const caseIncident = useFragment(caseFragment, caseIncidentData);

  const LOCAL_STORAGE_KEY_CASE_TASKS = `cases-${caseIncident.id}-caseTask`;

  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<CaseTasksLinesQuery$variables>(
    LOCAL_STORAGE_KEY_CASE_TASKS,
    {
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
    },
  );
  const { sortBy, orderAsc, filters } = viewStorage;
  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['Case-Incident']);
  const contextTaskFilters: FilterGroup = {
    mode: 'and',
    filters: [
      { key: 'entity_type', operator: 'eq', mode: 'or', values: ['Task'] },
      { key: 'objects', operator: 'eq', mode: 'or', values: [caseIncident.id] },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };
  const queryTaskPaginationOptions = {
    ...paginationOptions,
    filters: contextTaskFilters,
  } as unknown as CaseTasksLinesQuery$variables;
  const queryRef = useQueryLoading<CaseTasksLinesQuery>(
    caseTasksLinesQuery,
    queryTaskPaginationOptions,
  );

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
                  <Grid key={key} item xs={width} ref={ref}>
                    {queryRef && (
                      <React.Suspense
                        fallback={
                          <div style={{ height: '100%' }}>
                            <Typography
                              variant="h4"
                              gutterBottom={true}
                              style={{ marginBottom: 10 }}
                            >
                              {t_i18n('Tasks')}
                            </Typography>
                            <Paper
                              style={{
                                marginTop: theme.spacing(1),
                                padding: 0,
                                borderRadius: 4,
                              }}
                              variant="outlined"
                            >
                              <ListLines
                                sortBy={sortBy}
                                orderAsc={orderAsc}
                                handleSort={helpers.handleSort}
                                dataColumns={tasksDataColumns}
                                inline={true}
                                secondaryAction={true}
                              >
                                {Array(20)
                                  .fill(0)
                                  .map((_, idx) => (
                                    <CaseTasksLineDummy key={idx} />
                                  ))}
                              </ListLines>
                            </Paper>
                          </div>
                        }
                      >
                        <CaseTasksLines
                          queryRef={queryRef}
                          paginationOptions={queryTaskPaginationOptions}
                          caseId={caseIncident.id}
                          sortBy={sortBy}
                          orderAsc={orderAsc}
                          handleSort={helpers.handleSort}
                          defaultMarkings={convertMarkings(caseIncident)}
                          containerRef={ref}
                          enableReferences={enableReferences}
                        />
                      </React.Suspense>
                    )}
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
                        'Vulnerability',
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
    </>
  );
};

export default CaseIncident;
