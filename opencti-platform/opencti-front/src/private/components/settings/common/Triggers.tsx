import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import { BackupTableOutlined, CampaignOutlined } from '@mui/icons-material';
import Paper from '@mui/material/Paper';
import React, { FunctionComponent, useRef, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import TriggerLiveCreation from '../../profile/triggers/TriggerLiveCreation';
import ColumnsLinesTitles from '../../../../components/ColumnsLinesTitles';
import TriggersLines, { triggersLinesQuery } from '../../profile/triggers/TriggersLines';
import TriggerDigestCreation from '../../profile/triggers/TriggerDigestCreation';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';
import { TriggersLinesPaginationQuery, TriggersLinesPaginationQuery$variables } from '../../profile/triggers/__generated__/TriggersLinesPaginationQuery.graphql';
import SearchInput from '../../../../components/SearchInput';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { LOCAL_STORAGE_KEY_TRIGGERS } from '../../profile/Triggers';
import { TriggerLineDummy } from '../../profile/triggers/TriggerLine';
import { GqlFilterGroup, emptyFilterGroup } from '../../../../utils/filters/filtersUtils';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  createButton: {
    float: 'left',
    marginTop: -15,
  },
  paper: {
    margin: 0,
    padding: '15px',
    borderRadius: 4,
    position: 'relative',
    listStyleType: 'none',
  },
}));

interface TriggersProps {
  recipientId: string;
  filterKey: string;
}
const Triggers: FunctionComponent<TriggersProps> = ({
  recipientId,
  filterKey,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const ref = useRef(null);
  const {
    viewStorage,
    helpers,
    paginationOptions: paginationOptionsFromStorage,
  } = usePaginationLocalStorage<TriggersLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_TRIGGERS,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      filters: emptyFilterGroup,
      numberOfElements: {
        number: 0,
        symbol: '',
      },
    },
    true,
  );
  const { searchTerm, sortBy, orderAsc } = viewStorage;

  const paginationOptions = {
    ...paginationOptionsFromStorage,
    count: 25,
    includeAuthorities: true,
    filters: {
      mode: 'and',
      filters: [
        { key: [filterKey], values: [recipientId], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    } as GqlFilterGroup,
  };
  const queryRef = useQueryLoading<TriggersLinesPaginationQuery>(
    triggersLinesQuery,
    paginationOptions,
  );
  const dataColumns = {
    trigger_type: {
      label: 'Type',
      width: '10%',
      isSortable: true,
    },
    name: {
      label: 'Name',
      width: '15%',
      isSortable: true,
    },
    notifiers: {
      label: 'Notification',
      width: '20%',
      isSortable: true,
    },
    event_types: {
      label: 'Triggering on',
      width: '20%',
      isSortable: false,
    },
    filters: {
      label: 'Details',
      width: '35%',
      isSortable: false,
    },
  };
  const [openLive, setOpenLive] = useState(false);
  const [openDigest, setOpenDigest] = useState(false);
  return (
    <Grid item xs={12} style={{ marginTop: 10 }}>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
        {t_i18n('Triggers and Digests')}
      </Typography>
      <div style={{ float: 'right', marginTop: -12 }}>
        <SearchInput
          variant="thin"
          onSubmit={helpers.handleSearch}
          keyword={searchTerm}
        />
      </div>
      <Tooltip title={t_i18n('Add a live trigger')}>
        <IconButton
          aria-label="Add"
          className={classes.createButton}
          onClick={() => setOpenLive(true)}
          color="primary"
        >
          <CampaignOutlined fontSize="small" />
        </IconButton>
      </Tooltip>
      <TriggerLiveCreation
        paginationOptions={paginationOptions}
        open={openLive}
        handleClose={() => setOpenLive(false)}
        recipientId={recipientId}
      />
      <Tooltip title={t_i18n('Add a regular digest')}>
        <IconButton
          aria-label="Add"
          className={classes.createButton}
          onClick={() => setOpenDigest(true)}
          color="primary"
        >
          <BackupTableOutlined fontSize="small" />
        </IconButton>
      </Tooltip>
      <div className="clearfix" />
      <Paper
        ref={ref}
        variant="outlined"
        classes={{ root: classes.paper }}
      >
        <ColumnsLinesTitles
          dataColumns={dataColumns}
          sortBy={sortBy}
          orderAsc={orderAsc}
          handleSort={helpers.handleSort}
          secondaryAction={true}
        />
        {queryRef && (
          <React.Suspense
            fallback={(
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <TriggerLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
            )}
          >
            <TriggersLines
              queryRef={queryRef}
              containerRef={ref}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              bypassEditionRestriction={true}
            />
          </React.Suspense>
        )}
      </Paper>
      <TriggerDigestCreation
        paginationOptions={paginationOptions}
        open={openDigest}
        handleClose={() => setOpenDigest(false)}
        recipientId={recipientId}
      />
    </Grid>
  );
};

export default Triggers;
