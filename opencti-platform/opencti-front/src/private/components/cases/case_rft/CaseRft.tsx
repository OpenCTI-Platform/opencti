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
import { CaseTasksLinesQuery } from '../__generated__/CaseTasksLinesQuery.graphql';
import { CaseTasksFilter } from '../__generated__/CaseTasksRefetch.graphql';
import { CaseUtils_case$key } from '../__generated__/CaseUtils_case.graphql';
import CaseTasksLines, { caseTasksLinesQuery } from '../CaseTasksLines';
import { caseFragment } from '../CaseUtils';
import CaseRftDetails from './CaseRftDetails';
import CaseRftEdition from './CaseRftEdition';
import CaseRftPopover from './CaseRftPopover';

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
  const caseRftData = useFragment(caseFragment, data);

  const tasksFilters = {
    filters: [{
      key: ['objectContains' as CaseTasksFilter],
      values: [caseRftData.id],
    }],
  };
  const paginationOptions = {
    count: 25,
    filters: tasksFilters.filters,
  };
  const queryRef = useQueryLoading<CaseTasksLinesQuery>(caseTasksLinesQuery, paginationOptions);
  return (
    <div className={classes.container}>
      <ContainerHeader
        container={caseRftData}
        PopoverComponent={<CaseRftPopover id={caseRftData.id} />}
        enableSuggestions={false}
        disableSharing={true}
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
      </Grid>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
            style={{ marginTop: 25 }}
          >
            <Grid item={true} xs={12} style={{ paddingTop: 24 }}>
              <CaseTasksLines
                queryRef={queryRef}
                paginationOptions={paginationOptions}
                caseId={caseRftData.id}
                tasksFilters={tasksFilters}
                defaultMarkings={convertMarkings(caseRftData)}
              />
            </Grid>
          </Grid>
        </React.Suspense>
      )}
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
        style={{ marginTop: 25 }}
      >
        <Grid item={true} xs={12} style={{ paddingTop: 24 }}>
          <ContainerStixObjectsOrStixRelationships
            isSupportParticipation={false}
            container={caseRftData}
          />
        </Grid>
      </Grid>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
        style={{ marginTop: 25 }}
      >
        <Grid item={true} xs={6}>
          <StixCoreObjectExternalReferences stixCoreObjectId={caseRftData.id} />
        </Grid>
        <Grid item={true} xs={6}>
          <StixCoreObjectLatestHistory stixCoreObjectId={caseRftData.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={caseRftData.id}
        defaultMarking={(caseRftData.objectMarking?.edges ?? []).map(
          (edge) => edge.node,
        )}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <CaseRftEdition
          caseId={caseRftData.id}
        />
      </Security>
    </div>
  );
};

export default CaseRftComponent;
