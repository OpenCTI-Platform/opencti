import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent } from 'react';
import { useFragment } from 'react-relay';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { convertMarkings } from '../../../../utils/edition';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Security from '../../../../utils/Security';
import StixCoreObjectExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import ContainerHeader from '../../common/containers/ContainerHeader';
import ContainerStixObjectsOrStixRelationships from '../../common/containers/ContainerStixObjectsOrStixRelationships';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import {
  TasksFilter,
  CaseTasksLinesQuery,
  CaseTasksLinesQuery$variables,
} from '../tasks/__generated__/CaseTasksLinesQuery.graphql';
import { CaseUtils_case$key } from '../__generated__/CaseUtils_case.graphql';
import CaseTasksLines, { caseTasksLinesQuery } from '../tasks/CaseTasksLines';
import { caseFragment } from '../CaseUtils';
import CaseRftDetails from './CaseRftDetails';
import CaseRftEdition from './CaseRftEdition';
import CaseRftPopover from './CaseRftPopover';
import { useFormatter } from '../../../../components/i18n';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';

const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
  container: {
    margin: 0,
  },
}));

interface CaseRftProps {
  data: CaseUtils_case$key;
}

const CaseRftComponent: FunctionComponent<CaseRftProps> = ({ data }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const caseRftData = useFragment(caseFragment, data);

  const tasksFilters = {
    filters: [
      {
        key: ['objectContains' as TasksFilter],
        values: [caseRftData.id],
      },
    ],
  };
  const LOCAL_STORAGE_KEY_CASE_TASKS = `view-cases-${caseRftData.id}-caseTask`;

  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<CaseTasksLinesQuery$variables>(
    LOCAL_STORAGE_KEY_CASE_TASKS,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
    },
    tasksFilters.filters,
  );

  const { sortBy, orderAsc } = viewStorage;

  const queryRef = useQueryLoading<CaseTasksLinesQuery>(
    caseTasksLinesQuery,
    paginationOptions,
  );
  return (
    <div className={classes.container}>
      <ContainerHeader
        container={caseRftData}
        PopoverComponent={<CaseRftPopover id={caseRftData.id} />}
        enableSuggestions={false}
      />
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
            displayAssignees={true}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          {queryRef && (
            <React.Suspense
              fallback={<Loader variant={LoaderVariant.inElement} />}
            >
              <CaseTasksLines
                queryRef={queryRef}
                paginationOptions={paginationOptions}
                caseId={caseRftData.id}
                sortBy={sortBy}
                orderAsc={orderAsc}
                handleSort={helpers.handleSort}
                defaultMarkings={convertMarkings(caseRftData)}
              />
            </React.Suspense>
          )}
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <ContainerStixObjectsOrStixRelationships
            isSupportParticipation={false}
            container={caseRftData}
            types={['Incident', 'stix-sighting-relationship', 'Report']}
            title={t('Origin of the case')}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <ContainerStixObjectsOrStixRelationships
            isSupportParticipation={false}
            container={caseRftData}
            types={['Stix-Cyber-Observable']}
            title={t('Observables')}
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
        defaultMarkings={(caseRftData.objectMarking?.edges ?? []).map(
          (edge) => edge.node,
        )}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <CaseRftEdition caseId={caseRftData.id} />
      </Security>
    </div>
  );
};

export default CaseRftComponent;
