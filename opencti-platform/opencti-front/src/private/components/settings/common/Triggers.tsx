import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { BackupTableOutlined, CampaignOutlined } from '@mui/icons-material';
import Paper from '@mui/material/Paper';
import React, { FunctionComponent, useRef, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import TriggerLiveCreation from '../../profile/triggers/TriggerLiveCreation';
import ColumnsLinesTitles from '../../../../components/ColumnsLinesTitles';
import TriggersLines, {
  triggersLinesQuery,
} from '../../profile/triggers/TriggersLines';
import TriggerDigestCreation from '../../profile/triggers/TriggerDigestCreation';

import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';
import {
  TriggerFilter,
  TriggersLinesPaginationQuery,
  TriggersLinesPaginationQuery$variables,
} from '../../profile/triggers/__generated__/TriggersLinesPaginationQuery.graphql';
import SearchInput from '../../../../components/SearchInput';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { Filters } from '../../../../components/list_lines';
import { LOCAL_STORAGE_KEY_TRIGGERS } from '../../profile/Triggers';
import { TriggerLineDummy } from '../../profile/triggers/TriggerLine';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  createButton: {
    float: 'left',
    marginTop: -15,
  },
}));

interface TriggersProps {
  recipientId: string;
  filter: TriggerFilter;
}
const Triggers: FunctionComponent<TriggersProps> = ({
  recipientId,
  filter,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
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
      filters: {} as Filters,
      numberOfElements: {
        number: 0,
        symbol: '',
      },
    },
    undefined,
    true,
  );
  const { searchTerm, sortBy, orderAsc } = viewStorage;

  const paginationOptions = {
    ...paginationOptionsFromStorage,
    count: 25,
    includeAuthorities: true,
    filters: [{ key: [filter], values: [recipientId] }],
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
    outcomes: {
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
      width: '30%',
      isSortable: false,
    },
  };
  const [openLive, setOpenLive] = useState(false);
  const [openDigest, setOpenDigest] = useState(false);
  return (
    <Grid item={true} xs={12} style={{ marginTop: 30 }}>
      <Typography
        variant="h4"
        gutterBottom={true}
        style={{ float: 'left', marginRight: 12 }}
      >
        {t('Triggers and Digests')}
      </Typography>
      <div style={{ float: 'right', marginTop: -12 }}>
        <SearchInput
          variant="thin"
          onSubmit={helpers.handleSearch}
          keyword={searchTerm}
        />
      </div>
      <Tooltip title={t('Add a live trigger')}>
        <IconButton
          aria-label="Add"
          className={classes.createButton}
          onClick={() => setOpenLive(true)}
          size="large"
          color="secondary"
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
      <Tooltip title={t('Add a regular digest')}>
        <IconButton
          aria-label="Add"
          className={classes.createButton}
          onClick={() => setOpenDigest(true)}
          size="large"
          color="secondary"
        >
          <BackupTableOutlined fontSize="small" />
        </IconButton>
      </Tooltip>
      <div className="clearfix" />
      <Paper
        ref={ref}
        classes={{ root: classes.paper }}
        variant="outlined"
        style={{ marginTop: 0, maxHeight: 500, overflow: 'auto' }}
      >
        <ColumnsLinesTitles
          dataColumns={dataColumns}
          sortBy={sortBy}
          orderAsc={orderAsc}
          handleSort={helpers.handleSort}
        />
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((idx) => (
                    <TriggerLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
            }
          >
            <TriggersLines
              containerRef={ref}
              queryRef={queryRef}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
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
