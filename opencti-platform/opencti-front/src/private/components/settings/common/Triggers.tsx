import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { BackupTableOutlined, CampaignOutlined } from '@mui/icons-material';
import Paper from '@mui/material/Paper';
import React, { FunctionComponent, useRef, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import TriggerLiveCreation from '../../profile/triggers/TriggerLiveCreation';
import TriggerLineTitles from '../../profile/TriggerLineTitles';
import TriggersLines, {
  triggersLinesQuery,
} from '../../profile/triggers/TriggersLines';
import TriggerDigestCreation from '../../profile/triggers/TriggerDigestCreation';

import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';
import {
  TriggerFilter,
  TriggersLinesPaginationQuery,
} from '../../profile/triggers/__generated__/TriggersLinesPaginationQuery.graphql';

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
  const paginationOptions = {
    count: 25,
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
    <Grid item={true} xs={12} style={{ marginTop: 20 }} ref={ref}>
      <Typography
        variant="h4"
        gutterBottom={true}
        style={{ float: 'left', marginRight: 12 }}
      >
        {t('Triggers and Digests')}
      </Typography>
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
        classes={{ root: classes.paper }}
        variant="outlined"
        style={{ marginTop: 0 }}
      >
        <TriggerLineTitles dataColumns={dataColumns} />
        {queryRef && (
          <TriggersLines
            queryRef={queryRef}
            paginationOptions={paginationOptions}
            dataColumns={dataColumns}
            containerRef={ref}
          />
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
