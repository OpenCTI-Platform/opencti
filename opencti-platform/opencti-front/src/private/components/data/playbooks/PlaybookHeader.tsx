/*
Copyright (c) 2021-2024 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { useEffect, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { AutoAwesomeOutlined, CheckCircleOutlined, ErrorOutlined, ExpandLessOutlined, ExpandMoreOutlined, ManageHistoryOutlined } from '@mui/icons-material';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import Collapse from '@mui/material/Collapse';
import Badge from '@mui/material/Badge';
import { createRefetchContainer, graphql, RelayRefetchProp } from 'react-relay';
import { interval } from 'rxjs';
import DialogTitle from '@mui/material/DialogTitle';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import Drawer from '../../common/drawer/Drawer';
import { PlaybookHeader_playbook$data } from './__generated__/PlaybookHeader_playbook.graphql';
import { useFormatter } from '../../../../components/i18n';
import PlaybookPopover from './PlaybookPopover';
import { FIVE_SECONDS } from '../../../../utils/Time';
import Transition from '../../../../components/Transition';

const interval$ = interval(FIVE_SECONDS);

const useStyles = makeStyles(() => ({
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  status: {
    float: 'left',
    margin: '3px 0 0 5px',
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    height: 25,
    textTransform: 'uppercase',
    borderRadius: 4,
  },
  activity: {
    marginTop: -10,
    float: 'right',
  },
}));

const inlineStyles = {
  green: {
    backgroundColor: 'rgba(76, 175, 80, 0.08)',
    color: '#4caf50',
  },
  red: {
    backgroundColor: 'rgba(244, 67, 54, 0.08)',
    color: '#f44336',
  },
};

const playbookHeaderRefetchQuery = graphql`
  query PlaybookHeaderRefetchQuery($id: String!) {
    playbook(id: $id) {
      ...PlaybookHeader_playbook
    }
  }
`;

const PlaybookHeaderComponent = ({
  playbook,
  relay,
}: {
  playbook: PlaybookHeader_playbook$data;
  relay: RelayRefetchProp;
}) => {
  const classes = useStyles();
  useEffect(() => {
    // Refresh
    const subscription = interval$.subscribe(() => {
      relay.refetch({ id: playbook.id });
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, []);
  const [openLastExecutions, setOpenLastExecutions] = useState(false);
  const [openExecution, setOpenExecution] = useState<string | null>(null);
  const [rawData, setRawData] = useState<string | null | undefined>(null);
  const { t_i18n, nsdt } = useFormatter();
  return (
    <>
      <Typography
        variant="h1"
        gutterBottom={true}
        classes={{ root: classes.title }}
      >
        {playbook.name}
      </Typography>
      <div className={classes.popover}>
        <PlaybookPopover
          playbookId={playbook.id}
          running={playbook.playbook_running}
        />
      </div>
      <div className={classes.status}>
        <Chip
          classes={{ root: classes.chip }}
          style={
            playbook.playbook_running ? inlineStyles.green : inlineStyles.red
          }
          label={
            playbook.playbook_running
              ? t_i18n('Playbook is running')
              : t_i18n('Playbook is stopped')
          }
        />
      </div>
      <div className={classes.activity}>
        <ToggleButtonGroup
          size="small"
          color="secondary"
          value={openLastExecutions}
          exclusive={true}
          onChange={() => setOpenLastExecutions(!openLastExecutions)}
          style={{ margin: '7px 0 0 5px' }}
        >
          <ToggleButton value="cards" aria-label="cards">
            <Tooltip title={t_i18n('Open last execution traces')}>
              <Badge
                badgeContent={(playbook.last_executions ?? []).length}
                color="secondary"
              >
                <ManageHistoryOutlined color="primary" />
              </Badge>
            </Tooltip>
          </ToggleButton>
        </ToggleButtonGroup>
      </div>
      <Drawer
        open={openLastExecutions}
        onClose={() => setOpenLastExecutions(false)}
        title={t_i18n('Last execution traces')}
      >
        <List>
          {(playbook.last_executions ?? []).map((lastExecution) => {
            return (
              <React.Fragment key={lastExecution.id}>
                <ListItem
                  dense={true}
                  button={true}
                  divider={openExecution !== lastExecution.id}
                  onClick={() => setOpenExecution(openExecution ? null : lastExecution.id)
                  }
                >
                  <ListItemIcon>
                    <AutoAwesomeOutlined fontSize="small" color="primary" />
                  </ListItemIcon>
                  <ListItemText
                    primary={`${t_i18n('Execution at')} ${nsdt(
                      lastExecution.execution_start,
                    )}`}
                    secondary={`${(lastExecution.steps ?? []).length} ${t_i18n(
                      'steps executed',
                    )}`}
                  />
                  {openExecution === lastExecution.id ? (
                    <ExpandLessOutlined />
                  ) : (
                    <ExpandMoreOutlined />
                  )}
                </ListItem>
                <Collapse
                  in={openExecution === lastExecution.id}
                  timeout="auto"
                  unmountOnExit
                >
                  <List component="div" disablePadding={true}>
                    {(lastExecution.steps ?? []).map((step) => (
                      <ListItem
                        key={step.id}
                        dense={true}
                        button={true}
                        sx={{ pl: 4 }}
                        onClick={() => setRawData(step.error ?? step.bundle_or_patch)}
                      >
                        <ListItemIcon>
                          <Tooltip title={t_i18n(step.status)}>
                            {step.status === 'success' ? (
                              <CheckCircleOutlined
                                fontSize="small"
                                color="success"
                              />
                            ) : (
                              <ErrorOutlined fontSize="small" color="error" />
                            )}
                          </Tooltip>
                        </ListItemIcon>
                        <ListItemText
                          primary={step.message}
                          secondary={`${t_i18n('Execution ended at')} ${nsdt(
                            step.out_timestamp,
                          )}`}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Collapse>
              </React.Fragment>
            );
          })}
        </List>
      </Drawer>
      <Dialog
        PaperProps={{ elevation: 1 }}
        TransitionComponent={Transition}
        open={rawData !== null}
        onClose={() => setRawData(null)}
        fullWidth={true}
        maxWidth="md"
      >
        <DialogTitle>{t_i18n('Raw data')}</DialogTitle>
        <DialogContent>
          <pre>{rawData}</pre>
        </DialogContent>
      </Dialog>
      <div className="clearfix" />
    </>
  );
};

const PlaybookHeader = createRefetchContainer(
  PlaybookHeaderComponent,
  {
    playbook: graphql`
      fragment PlaybookHeader_playbook on Playbook {
        id
        entity_type
        name
        description
        playbook_running
        last_executions {
          id
          playbook_id
          execution_start
          steps {
            id
            message
            status
            out_timestamp
            duration
            bundle_or_patch
            error
          }
        }
      }
    `,
  },
  playbookHeaderRefetchQuery,
);

export default PlaybookHeader;
