import React, { useMemo } from 'react';
import { Alert, Collapse, Grid, IconButton, List, ListItem, Box, Select, MenuItem, Tooltip, Typography } from '@mui/material';
import { TransitionGroup } from 'react-transition-group';
import { DeleteOutlined, UploadFileOutlined } from '@mui/icons-material';
import { FileWithConnectors } from '@components/common/files/import_files/ImportFilesUploader';
import { CSV_MAPPER_NAME } from '@components/common/files/import_files/ImportFilesDialog';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../../components/i18n';
import { ImportFilesDialogQuery$data } from './__generated__/ImportFilesDialogQuery.graphql';
import type { Theme } from '../../../../../components/Theme';

interface ImportFilesListProps {
  files: FileWithConnectors[];
  connectorsForImport: ImportFilesDialogQuery$data['connectorsForImport'];
  onChange: (updatedFiles: FileWithConnectors[]) => void;
}

const ImportFilesList: React.FC<ImportFilesListProps> = ({ files, connectorsForImport, onChange }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const removeFile = (fileName: string) => {
    onChange(files.filter(({ file }) => file.name !== fileName));
  };

  const handleConnectorChange = (fileName: string, selectedConnectorIds: string[]) => {
    const updatedFiles = files.map(({ file, connectors, configuration }) => {
      if (file.name === fileName) {
        return {
          file,
          connectors: connectorsForImport
            ?.filter((connector) => connector?.id && selectedConnectorIds.includes(connector.id))
            .map((connector) => ({ id: connector?.id ?? '', name: connector?.name ?? '' })) || [],
        };
      }
      return { file, connectors, configuration };
    });
    onChange(updatedFiles);
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
    onChange(updatedFiles);
  };

  const isConfigurationColumn = useMemo(() => {
    return files.some(({ connectors }) => {
      return connectors?.some((connector) => connector?.name === CSV_MAPPER_NAME);
    });
  }, [files]);

  return (
    <List>
      <TransitionGroup>
        {files.length > 0 && (
          <Collapse key="header" >
            <ListItem divider>
              <Grid container columnSpacing={2}>
                <Grid item xs={0.5}></Grid>
                <Grid item xs={isConfigurationColumn ? 5 : 8}>
                  <Typography fontWeight="bold">
                    {t_i18n('Files')}
                  </Typography>
                </Grid>

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
                    <UploadFileOutlined color="primary"/>
                  </Grid>

                  {/* Column 2: File Name */}
                  <Grid item xs={isConfigurationColumn ? 5 : 8}>
                    <Tooltip title={file.name}>
                      <Box sx={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', width: '100%' }}>
                        {file.name}
                      </Box>
                    </Tooltip>
                  </Grid>

                  {canSelectConnectors ? (
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
                            <MenuItem key={connector?.id} value={connector?.id}
                              disabled={!connector?.active || !connector?.connector_scope?.includes(file.type)}
                            >
                              {connector?.name}
                            </MenuItem>
                          ))}
                        </Select>
                      </Grid>

                      {/* Column 4: Select - CSV Mapper */}
                      {isConfigurationColumn
                        && (
                          <Grid item xs={3}>
                            {!!connectors.filter((c) => c?.name === CSV_MAPPER_NAME).length && (
                              <Select
                                variant="standard"
                                fullWidth
                                value={configuration || ''}
                                onChange={(e) => handleMapperChange(file.name, e.target.value as string)}
                                error={!configuration} // ✅ Adds red border on error
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
                  )}

                  {/* Column 5: Delete Button */}
                  <Grid item xs={0.5}>
                    <IconButton edge="end" onClick={() => removeFile(file.name)} color="primary">
                      <DeleteOutlined/>
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
