import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import React, { useRef } from 'react';
import { useFragment } from 'react-relay';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import useHelper from 'src/utils/hooks/useHelper';
import { convertMarkings } from '../../../../utils/edition';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Security from '../../../../utils/Security';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import ContainerStixObjectsOrStixRelationships from '../../common/containers/ContainerStixObjectsOrStixRelationships';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import { CaseUtils_case$key } from '../__generated__/CaseUtils_case.graphql';
import CaseTasksLines, { caseTasksLinesQuery } from '../tasks/CaseTasksLines';
import { caseFragment } from '../CaseUtils';
import CaseRfiDetails from './CaseRfiDetails';
import CaseRfiEdition from './CaseRfiEdition';
import { useFormatter } from '../../../../components/i18n';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { CaseTasksLinesQuery, CaseTasksLinesQuery$variables } from '../tasks/__generated__/CaseTasksLinesQuery.graphql';
import ListLines from '../../../../components/list_lines/ListLines';
import { tasksDataColumns } from '../tasks/TasksLine';
import { CaseTasksLineDummy } from '../tasks/CaseTasksLine';
import { isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  paper: {
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 4,
  },
}));

interface CaseRfiProps {
  caseRfiData: CaseUtils_case$key;
  enableReferences: boolean;
}

const CaseRfi: React.FC<CaseRfiProps> = ({ caseRfiData, enableReferences }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const ref = useRef(null);
  const caseRfi = useFragment(caseFragment, caseRfiData);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const overviewLayoutCustomization = useOverviewLayoutCustomization(caseRfi.entity_type);

  const LOCAL_STORAGE_KEY = `cases-${caseRfi.id}-caseTask`;
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<CaseTasksLinesQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
    },
  );
  const { sortBy, orderAsc, filters } = viewStorage;

  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['Case-Rfi']);
  const contextTaskFilters: FilterGroup = {
    mode: 'and',
    filters: [
      { key: 'entity_type', operator: 'eq', mode: 'or', values: ['Task'] },
      { key: 'objects', operator: 'eq', mode: 'or', values: [caseRfi.id] },
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
  return (
    <>
      <Grid
        container={true}
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
                            <Paper classes={{ root: classes.paper }} variant="outlined">
                              <ListLines
                                helpers={helpers}
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
                          caseId={caseRfi.id}
                          sortBy={sortBy}
                          orderAsc={orderAsc}
                          handleSort={helpers.handleSort}
                          defaultMarkings={convertMarkings(caseRfi)}
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
