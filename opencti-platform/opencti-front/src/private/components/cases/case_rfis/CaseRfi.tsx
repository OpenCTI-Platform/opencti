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

interface CaseRfiProps {
  data: CaseUtils_case$key;
}

const CaseRfiComponent: FunctionComponent<CaseRfiProps> = ({ data }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const ref = useRef(null);
  const caseRfiData = useFragment(caseFragment, data);

  const LOCAL_STORAGE_KEY = `cases-${caseRfiData.id}-caseTask`;
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
      { key: 'objects', operator: 'eq', mode: 'or', values: [caseRfiData.id] },
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
          <CaseRfiDetails caseRfiData={caseRfiData} />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview
            stixDomainObject={caseRfiData}
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
                caseId={caseRfiData.id}
                sortBy={sortBy}
                orderAsc={orderAsc}
                handleSort={helpers.handleSort}
                defaultMarkings={convertMarkings(caseRfiData)}
                containerRef={ref}
              />
            </React.Suspense>
          )}
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <ContainerStixObjectsOrStixRelationships
            isSupportParticipation={false}
            container={caseRfiData}
            types={['Incident', 'stix-sighting-relationship', 'Report']}
            title={t_i18n('Origin of the case')}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <ContainerStixObjectsOrStixRelationships
            isSupportParticipation={false}
            container={caseRfiData}
            types={['Stix-Cyber-Observable']}
            title={t_i18n('Observables')}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <ContainerStixObjectsOrStixRelationships
            isSupportParticipation={false}
            container={caseRfiData}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectExternalReferences stixCoreObjectId={caseRfiData.id} />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectLatestHistory stixCoreObjectId={caseRfiData.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={caseRfiData.id}
        defaultMarkings={caseRfiData.objectMarking ?? []}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <CaseRfiEdition caseId={caseRfiData.id} />
      </Security>
    </>
  );
};

export default CaseRfiComponent;
