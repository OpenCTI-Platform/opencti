import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, useRef } from 'react';
import { useFragment } from 'react-relay';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import { convertMarkings } from '../../../../utils/edition';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Security from '../../../../utils/Security';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import ContainerStixObjectsOrStixRelationships from '../../common/containers/ContainerStixObjectsOrStixRelationships';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import { CaseTasksLinesQuery, CaseTasksLinesQuery$variables } from '../tasks/__generated__/CaseTasksLinesQuery.graphql';
import { CaseUtils_case$key } from '../__generated__/CaseUtils_case.graphql';
import CaseTasksLines, { caseTasksLinesQuery } from '../tasks/CaseTasksLines';
import { caseFragment } from '../CaseUtils';
import CaseRftDetails from './CaseRftDetails';
import CaseRftEdition from './CaseRftEdition';
import { useFormatter } from '../../../../components/i18n';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import ListLines from '../../../../components/list_lines/ListLines';
import { tasksDataColumns } from '../tasks/TasksLine';
import { CaseTasksLineDummy } from '../tasks/CaseTasksLine';
import { isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 4,
  },
}));

interface CaseRftProps {
  data: CaseUtils_case$key;
}

const CaseRftComponent: FunctionComponent<CaseRftProps> = ({ data }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const ref = useRef(null);
  const caseRftData = useFragment(caseFragment, data);
  const LOCAL_STORAGE_KEY_CASE_TASKS = `cases-${caseRftData.id}-caseTask`;
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<CaseTasksLinesQuery$variables>(
    LOCAL_STORAGE_KEY_CASE_TASKS,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
    },
  );
  const { sortBy, orderAsc, filters } = viewStorage;

  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['Case-Rft']);
  const contextTaskFilters: FilterGroup = {
    mode: 'and',
    filters: [
      { key: 'entity_type', operator: 'eq', mode: 'or', values: ['Task'] },
      { key: 'objects', operator: 'eq', mode: 'or', values: [caseRftData.id] },
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
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <CaseRftDetails caseRftData={caseRftData} />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview
            stixDomainObject={caseRftData}
            displayAssignees
            displayParticipants
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }} ref={ref}>
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
                caseId={caseRftData.id}
                sortBy={sortBy}
                orderAsc={orderAsc}
                handleSort={helpers.handleSort}
                defaultMarkings={convertMarkings(caseRftData)}
                containerRef={ref}
              />
            </React.Suspense>
          )}
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <ContainerStixObjectsOrStixRelationships
            isSupportParticipation={false}
            container={caseRftData}
            types={['Incident', 'stix-sighting-relationship', 'Report']}
            title={t_i18n('Origin of the case')}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <ContainerStixObjectsOrStixRelationships
            isSupportParticipation={false}
            container={caseRftData}
            types={['Stix-Cyber-Observable']}
            title={t_i18n('Observables')}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <ContainerStixObjectsOrStixRelationships
            isSupportParticipation={false}
            container={caseRftData}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectExternalReferences stixCoreObjectId={caseRftData.id} />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectLatestHistory stixCoreObjectId={caseRftData.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={caseRftData.id}
        defaultMarkings={caseRftData.objectMarking ?? []}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <CaseRftEdition caseId={caseRftData.id} />
      </Security>
    </>
  );
};

export default CaseRftComponent;
