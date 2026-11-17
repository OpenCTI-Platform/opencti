/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import Dialog from '@common/dialog/Dialog';
import Tag from '@common/tag/Tag';
import PlaybookEdition from '@components/data/playbooks/PlaybookEdition';
import { CheckCircleOutlined, ErrorOutlined, ExpandLessOutlined, ExpandMoreOutlined, ManageHistoryOutlined } from '@mui/icons-material';
import { Stack } from '@mui/material';
import Badge from '@mui/material/Badge';
import Collapse from '@mui/material/Collapse';
import List from '@mui/material/List';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/material/styles';
import React, { useEffect, useState } from 'react';
import { Switch, Text, Tooltip as FdsTooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { createRefetchContainer, graphql, RelayRefetchProp } from 'react-relay';
import { interval } from 'rxjs';
import ItemIcon from '../../../../components/ItemIcon';
import { Theme } from '../../../../components/Theme';
import TitleMainEntity from '../../../../components/common/typography/TitleMainEntity';
import { useFormatter } from '../../../../components/i18n';
import { FIVE_SECONDS } from '../../../../utils/Time';
import Drawer from '../../common/drawer/Drawer';
import PlaybookPopover from './PlaybookPopover';
import { PlaybookHeader_playbook$data } from './__generated__/PlaybookHeader_playbook.graphql';
import type { PlaybookEditorMode } from './hooks/usePlaybookEditMode';

const interval$ = interval(FIVE_SECONDS);

const playbookHeaderRefetchQuery = graphql`
  query PlaybookHeaderRefetchQuery($id: String!) {
    playbook(id: $id) {
      ...PlaybookHeader_playbook
    }
  }
`;

// The creator and last-modified line under the title. The first creator is the one who created the
// playbook; without one (an old playbook, a creator removed) the line starts at the date.
export const PlaybookMetadataLine = ({ creatorName, createdAt, updatedAt }: {
  creatorName?: string | null;
  createdAt?: string | null;
  updatedAt?: string | null;
}) => {
  const { t_i18n, fsd, mhd } = useFormatter();
  const theme = useTheme<Theme>();
  // Whole sentences in the catalogs (word order differs by language); the name is a rich value.
  const name = creatorName ? <Text variant="content-compact-medium" as="span" key="name">{creatorName}</Text> : null;
  const created = name
    ? t_i18n('Created by {name} on {date}', { values: { name, date: fsd(createdAt) } })
    : t_i18n('Created on {date}', { values: { date: fsd(createdAt) } });
  return (
    <Text variant="content-compact" data-testid="playbook-metadata-line" style={{ color: theme.palette.text?.secondary, margin: 0 }}>
      {created}
      {' \u00b7 '}
      {t_i18n('Last modified {date}', { values: { date: mhd(updatedAt) } })}
    </Text>
  );
};

const PlaybookHeaderComponent = ({
  playbook,
  relay,
  mode,
  onModeChange,
}: {
  playbook: PlaybookHeader_playbook$data;
  relay: RelayRefetchProp;
  mode?: PlaybookEditorMode;
  // Given only to users who can manage playbooks: the others stay in view mode with no switch.
  onModeChange?: (mode: PlaybookEditorMode) => void;
}) => {
  const theme = useTheme<Theme>();
  const inlineStyles = {
    green: {
      color: theme.palette.severity.low,
    },
    red: {
      color: theme.palette.severity.critical,
    },
  };

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
  const { t_i18n, nsdt, n } = useFormatter();
  return (
    <>
      <Stack
        direction="row"
        sx={{
          alignItems: 'center',
          gap: 1,
        }}
      >
        <Stack sx={{ flex: 1, minWidth: 0, gap: 0.5 }}>
          <Stack
            direction="row"
            sx={{
              alignItems: 'center',
              gap: 1,
            }}
          >
            <TitleMainEntity>
              {playbook.name}
            </TitleMainEntity>
            <Tag
              {...(playbook.playbook_running ? inlineStyles.green : inlineStyles.red)}
              label={
                playbook.playbook_running
                  ? t_i18n('Playbook is running')
                  : t_i18n('Playbook is stopped')
              }
              labelTextTransform="none"
            />
          </Stack>
          <PlaybookMetadataLine
            creatorName={playbook.creators?.[0]?.name}
            createdAt={playbook.created_at}
            updatedAt={playbook.updated_at}
          />
        </Stack>
        {onModeChange && (
          <FdsTooltip>
            <TooltipTrigger asChild>
              <span style={{ display: 'inline-flex' }}>
                <Switch
                  data-testid="playbook-edit-mode"
                  label={t_i18n('Edit mode')}
                  checked={mode === 'edit'}
                  onCheckedChange={(checked) => onModeChange(checked ? 'edit' : 'view')}
                />
              </span>
            </TooltipTrigger>
            <TooltipContent>{mode === 'edit' ? t_i18n('Edit mode') : t_i18n('View only')}</TooltipContent>
          </FdsTooltip>
        )}
        <ToggleButtonGroup
          size="small"
          color="secondary"
          value={openLastExecutions}
          exclusive={true}
          onChange={() => setOpenLastExecutions(!openLastExecutions)}
        >
          <ToggleButton
            value="cards"
            aria-label="cards"
            style={{ padding: '5px' }}
          >
            <Stack
              direction="row"
              sx={{
                alignItems: 'center',
                gap: 1,
              }}
            >
              <Tag
                label={`${n(playbook.queue_messages)} ${t_i18n('messages in queue')}`}
                labelTextTransform="none"
              />
              <Tooltip title={t_i18n('Open last execution traces')}>
                <Badge
                  badgeContent={(playbook.last_executions ?? []).length}
                  color="secondary"
                >
                  <ManageHistoryOutlined fontSize="small" color="primary" />
                </Badge>
              </Tooltip>
            </Stack>
          </ToggleButton>
        </ToggleButtonGroup>
        <PlaybookPopover
          playbookId={playbook.id}
          running={!!playbook.playbook_running}
        />
        <PlaybookEdition id={playbook.id} />
      </Stack>
      <Drawer
        open={openLastExecutions}
        onClose={() => setOpenLastExecutions(false)}
        title={t_i18n('Last execution traces')}
      >
        <List>
          {(playbook.last_executions ?? []).map((lastExecution) => {
            return (
              <React.Fragment key={lastExecution.id}>
                <ListItemButton
                  dense={true}
                  divider={openExecution !== lastExecution.id}
                  onClick={() => setOpenExecution(openExecution ? null : lastExecution.id)
                  }
                  aria-expanded={openExecution === lastExecution.id}
                >
                  <ListItemIcon style={{ marginLeft: 10 }}>
                    <ItemIcon type="Playbook" color={theme.palette.primary.main} />
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
                </ListItemButton>
                <Collapse
                  in={openExecution === lastExecution.id}
                  timeout="auto"
                  unmountOnExit
                >
                  <List component="div" disablePadding={true}>
                    {(lastExecution.steps ?? []).map((step) => (
                      <ListItemButton
                        key={step.id}
                        dense={true}
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
                      </ListItemButton>
                    ))}
                  </List>
                </Collapse>
              </React.Fragment>
            );
          })}
          {(playbook.last_executions ?? []).length > 0 ? (
            <div style={{ paddingTop: 10 }}>
              {t_i18n('Last 20 execution traces are displayed above')}
            </div>
          ) : (
            <div>
              {t_i18n('There are no execution traces to display')}
            </div>
          )}
        </List>
      </Drawer>
      <Dialog
        open={rawData !== null}
        onClose={() => setRawData(null)}
        title={t_i18n('Raw data')}
      >
        <pre>{rawData}</pre>
      </Dialog>
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
        created_at
        updated_at
        creators {
          id
          name
        }
        playbook_running
        queue_messages
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
