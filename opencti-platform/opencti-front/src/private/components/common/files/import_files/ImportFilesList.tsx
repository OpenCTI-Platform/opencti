import React, { useEffect, useMemo, useState } from 'react';
import { Alert, Box, Collapse, Grid, IconButton, List, ListItem, MenuItem, Select, Tooltip, Typography } from '@mui/material';
import { TransitionGroup } from 'react-transition-group';
import { DeleteOutlined, UploadFileOutlined } from '@mui/icons-material';
import { CSV_MAPPER_NAME } from '@components/common/files/import_files/ImportFilesDialog';
import { useTheme } from '@mui/styles';
import { useImportFilesContext } from '@components/common/files/import_files/ImportFilesContext';
import { ImportFilesContextQuery$data } from '@components/common/files/import_files/__generated__/ImportFilesContextQuery.graphql';
import { useChatbot } from '@components/chatbox/ChatbotContext';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import { AgentOption, fetchAgentsForIntent, isXtmOneIntentWithoutAgents } from '../../../../../utils/ai/agentApi';

interface ImportFilesListProps {
  connectorsForImport: ImportFilesContextQuery$data['connectorsForImport'];
}

const ImportFilesList: React.FC<ImportFilesListProps> = ({ connectorsForImport }) => {
  const theme = useTheme<Theme>();
  const { files, setFiles, importMode } = useImportFilesContext();
  const { t_i18n } = useFormatter();
  const { xtmOneConfigured } = useChatbot();

  // Track loaded agents per intent
  const [agentsByIntent, setAgentsByIntent] = useState<Record<string, AgentOption[]>>({});

  // Agent count for an intent, or `undefined` while it has not been fetched yet.
  // Uses an own-property check so an intent that collides with a prototype key
  // (e.g. `constructor`, `toString`) can never read a non-array off the prototype.
  const agentCountForIntent = (intent?: string | null): number | undefined => {
    if (!intent || !Object.prototype.hasOwnProperty.call(agentsByIntent, intent)) return undefined;
    return agentsByIntent[intent].length;
  };

  // A connector is only blocked when XTM One is configured but the intent has no
  // agent. When XTM One is off, intent connectors stay usable via their legacy path.
  const connectorMissingAgent = (intent?: string | null): boolean => (
    isXtmOneIntentWithoutAgents(xtmOneConfigured, intent, agentCountForIntent(intent))
  );

  // Collect unique xtm_one_intent values from ALL available connectors (not just selected)
  const allIntents = useMemo(() => {
    const intents = new Set<string>();
    for (const connector of connectorsForImport ?? []) {
      if (connector?.xtm_one_intent) {
        intents.add(connector.xtm_one_intent);
      }
    }
    return Array.from(intents);
  }, [connectorsForImport]);

  // Fetch agents for all intents at mount time. Only when XTM One is configured:
  // otherwise intent connectors run in legacy mode and need no agent catalog.
  useEffect(() => {
    if (xtmOneConfigured !== true) return;
    for (const intent of allIntents) {
      if (!agentsByIntent[intent]) {
        fetchAgentsForIntent(intent).then((agents) => {
          setAgentsByIntent((prev) => ({ ...prev, [intent]: agents }));
        });
      }
    }
  }, [allIntents, xtmOneConfigured]);

  // Auto-preselect first agent for files with XTM One connectors that have no configuration yet
  useEffect(() => {
    if (Object.keys(agentsByIntent).length === 0) return;
    let changed = false;
    const updatedFiles = files.map(({ file, connectors, configuration }) => {
      if (configuration) return { file, connectors, configuration };
      const xtmConnector = connectors?.find((c) => {
        const full = connectorsForImport?.find((fc) => fc?.id === c.id);
        return full?.xtm_one_intent;
      });
      if (xtmConnector) {
        const full = connectorsForImport?.find((fc) => fc?.id === xtmConnector.id);
        const agents = full?.xtm_one_intent ? agentsByIntent[full.xtm_one_intent] : undefined;
        if (agents && agents.length > 0) {
          changed = true;
          return { file, connectors, configuration: JSON.stringify({ agent_slug: agents[0].slug }) };
        }
      }
      return { file, connectors, configuration };
    });
    if (changed) setFiles(updatedFiles);
  }, [files, agentsByIntent, connectorsForImport]);

  const removeFile = (fileName: string) => {
    setFiles(files.filter(({ file }) => file.name !== fileName));
  };

  const handleConnectorChange = (fileName: string, selectedConnectorIds: string[]) => {
    const updatedFiles = files.map(({ file, connectors, configuration }) => {
      if (file.name === fileName) {
        const newConnectors = connectorsForImport
          ?.filter((connector) => connector?.id && selectedConnectorIds.includes(connector.id))
          .map((connector) => ({ id: connector?.id ?? '', name: connector?.name ?? '' })) || [];
        // Auto-select first agent when a XTM One connector is added
        let newConfiguration = configuration;
        const xtmConnector = connectorsForImport?.find(
          (c) => c?.id && selectedConnectorIds.includes(c.id) && c?.xtm_one_intent,
        );
        if (xtmConnector?.xtm_one_intent) {
          const agents = agentsByIntent[xtmConnector.xtm_one_intent];
          if (agents && agents.length > 0 && !configuration) {
            newConfiguration = JSON.stringify({ agent_slug: agents[0].slug });
          }
        }
        return { file, connectors: newConnectors, configuration: newConfiguration };
      }
      return { file, connectors, configuration };
    });
    setFiles(updatedFiles);
  };

  const handleMapperChange = (fileName: string, selectedMapper: string) => {
    const updatedFiles = files.map(({ file, connectors, configuration }) => {
      if (file.name === fileName) {
        return {
          file,
          connectors,
          configuration: selectedMapper,
        };
      }
      return { file, connectors, configuration };
    });
    setFiles(updatedFiles);
  };

  const handleAgentChange = (fileName: string, agentSlug: string) => {
    const updatedFiles = files.map(({ file, connectors, configuration }) => {
      if (file.name === fileName) {
        return {
          file,
          connectors,
          configuration: agentSlug ? JSON.stringify({ agent_slug: agentSlug }) : undefined,
        };
      }
      return { file, connectors, configuration };
    });
    setFiles(updatedFiles);
  };

  // Helper to get the XTM One intent for a file's selected connectors
  const getXtmOneIntentForFile = (fileConnectors?: { id: string; name: string }[]) => {
    for (const connector of fileConnectors ?? []) {
      const fullConnector = connectorsForImport?.find((c) => c?.id === connector?.id);
      if (fullConnector?.xtm_one_intent) {
        return fullConnector.xtm_one_intent;
      }
    }
    return null;
  };

  // Helper to parse agent_slug from configuration JSON
  const getAgentSlugFromConfig = (configuration?: string) => {
    if (!configuration) return '';
    try {
      const config = JSON.parse(configuration);
      return config.agent_slug ?? '';
    } catch {
      return '';
    }
  };

  const isConfigurationColumn = useMemo(() => {
    return files.some(({ connectors }) => {
      const hasCsvMapper = connectors?.some((connector) => connector?.name === CSV_MAPPER_NAME);
      const hasXtmOne = connectors?.some((connector) => {
        const fullConnector = connectorsForImport?.find((c) => c?.id === connector?.id);
        return fullConnector?.xtm_one_intent && (agentsByIntent[fullConnector.xtm_one_intent]?.length ?? 0) > 0;
      });
      return hasCsvMapper || hasXtmOne;
    });
  }, [files, connectorsForImport, agentsByIntent]);

  const fileNameColumnSize = useMemo(() => {
    if (importMode === 'auto') return 11;
    if (isConfigurationColumn) return 5;
    return 8;
  }, [importMode, isConfigurationColumn]);

  return (
    <List>
      <TransitionGroup>
        {files.length > 0 && (
          <Collapse key="header">
            <ListItem divider>
              <Grid container columnSpacing={2}>
                <Grid item xs={0.5}></Grid>
                <Grid item xs={fileNameColumnSize}>
                  <Typography fontWeight="bold">
                    {t_i18n('Files')}
                  </Typography>
                </Grid>
                {importMode !== 'auto' && (
                  <>
                    <Grid item xs={3}>
                      <Typography fontWeight="bold">
                        {t_i18n('Connectors')}
                      </Typography>
                    </Grid>

                    {isConfigurationColumn && (
                      <Grid item xs={3}>
                        <Typography fontWeight="bold">
                          {t_i18n('Configuration')}
                        </Typography>
                      </Grid>
                    )}
                  </>
                )}
                <Grid item xs={0.5}></Grid>
              </Grid>
            </ListItem>
          </Collapse>
        )}

        {files.map(({ file, connectors = [], configuration }) => {
          const canSelectConnectors = !!connectorsForImport
            ?.find((connector) => connector?.connector_scope?.includes(file.type));

          return (
            <Collapse key={file.name}>
              <ListItem divider dense>
                <Grid container alignItems="center" columnSpacing={2}>
                  {/* Column 1: File Icon */}
                  <Grid item xs={0.5} sx={{ display: 'flex' }}>
                    <UploadFileOutlined color="primary" />
                  </Grid>

                  {/* Column 2: File Name */}
                  <Grid item xs={fileNameColumnSize}>
                    <Tooltip title={file.name}>
                      <Box sx={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', width: '100%' }}>
                        {file.name}
                      </Box>
                    </Tooltip>
                  </Grid>
                  {importMode !== 'auto' && (
                    <>
                      {
                        canSelectConnectors ? (
                          <>
                            {/* Column 3: Select - Show all connectors but disable those that haven't matching file type */}
                            <Grid item xs={3}>
                              <Select
                                variant="standard"
                                fullWidth
                                multiple
                                displayEmpty
                                renderValue={(selectedIds) => {
                                  if (selectedIds.length === 0) {
                                    return canSelectConnectors ? t_i18n('No active connectors') : t_i18n('Select a connector');
                                  }

                                  // Displays connectors name
                                  return selectedIds
                                    .map((id) => connectorsForImport?.find((c) => c?.id === id)?.name)
                                    .join(', ');
                                }}
                                value={connectors?.map((c) => c?.id)}
                                onChange={(e) => handleConnectorChange(file.name, e.target.value as string[])}
                              >
                                <MenuItem value="" disabled>
                                  {t_i18n('Select a connector')}
                                </MenuItem>
                                {connectorsForImport?.map((connector) => (
                                  <MenuItem
                                    key={connector?.id}
                                    value={connector?.id}
                                    disabled={
                                      !connector?.active
                                      || !connector?.connector_scope?.includes(file.type)
                                      || connectorMissingAgent(connector?.xtm_one_intent)
                                    }
                                  >
                                    {connector?.name}
                                    {connectorMissingAgent(connector?.xtm_one_intent)
                                      ? ` (${t_i18n('No agent available')})`
                                      : ''}
                                  </MenuItem>
                                ))}
                              </Select>
                            </Grid>

                            {/* Column 4: Configuration (CSV Mapper or XTM One Agent) */}
                            {isConfigurationColumn
                              && (
                                <Grid item xs={3}>
                                  {!!connectors.filter((c) => c?.name === CSV_MAPPER_NAME).length && (
                                    <Select
                                      variant="standard"
                                      fullWidth
                                      value={configuration || ''}
                                      onChange={(e) => handleMapperChange(file.name, e.target.value as string)}
                                      error={!configuration}
                                      displayEmpty
                                      sx={{
                                        '& .MuiSelect-select': {
                                          color: !configuration ? theme.palette.error.main : 'inherit',
                                        },
                                      }}
                                    >
                                      <MenuItem value="" disabled>
                                        {t_i18n('Select a configuration')}
                                      </MenuItem>
                                      {connectorsForImport
                                        ?.find((connector) => connector?.name === CSV_MAPPER_NAME)
                                        ?.configurations?.map((mapper) => (
                                          <MenuItem key={mapper?.id} value={mapper?.configuration}>
                                            {mapper?.name}
                                          </MenuItem>
                                        ))}
                                    </Select>
                                  )}
                                  {(() => {
                                    const intent = getXtmOneIntentForFile(connectors);
                                    const agents = intent ? agentsByIntent[intent] : null;
                                    if (!intent || !agents || agents.length === 0) return null;
                                    return (
                                      <Select
                                        variant="standard"
                                        fullWidth
                                        value={getAgentSlugFromConfig(configuration)}
                                        onChange={(e) => handleAgentChange(file.name, e.target.value as string)}
                                        displayEmpty
                                      >
                                        <MenuItem value="" disabled>
                                          {t_i18n('Select agent')}
                                        </MenuItem>
                                        {agents.map((agent) => (
                                          <MenuItem key={agent.id} value={agent.slug}>
                                            {agent.name}
                                          </MenuItem>
                                        ))}
                                      </Select>
                                    );
                                  })()}
                                </Grid>
                              )}
                          </>
                        ) : (
                          <Grid item xs={isConfigurationColumn ? 6 : 3}>
                            <Alert
                              variant="outlined"
                              severity="warning"
                              sx={{
                                border: 'none',
                                padding: 0,
                                backgroundColor: 'transparent',
                                boxShadow: 'none',
                              }}
                            >
                              {t_i18n('No connector was found to process this file type')}
                            </Alert>
                          </Grid>
                        )
                      }
                    </>
                  )}
                  {/* Column 5: Delete Button */}
                  <Grid item xs={0.5}>
                    <IconButton edge="end" onClick={() => removeFile(file.name)} color="primary">
                      <DeleteOutlined />
                    </IconButton>
                  </Grid>
                </Grid>
              </ListItem>
            </Collapse>
          );
        })}
      </TransitionGroup>
    </List>
  );
};

export default ImportFilesList;
