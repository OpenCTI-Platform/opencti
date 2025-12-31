import React, { Suspense, useCallback, useEffect, useMemo, useState } from 'react';
import Alert from '@mui/material/Alert';
import Drawer from '@components/common/drawer/Drawer';
import { useTheme } from '@mui/styles';
import Chip from '@mui/material/Chip';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { DrawerProps, Tooltip } from '@mui/material';
import IconButton from '@common/button/IconButton';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import { ArchitectureOutlined, DeleteOutlined } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import LaunchImportDialog from '@components/common/files/LaunchImportDialog';
import { ImportWorkbenchesContentFileLine_file$data } from '@components/data/import/__generated__/ImportWorkbenchesContentFileLine_file.graphql';
import { ImportFilesContentFileLine_file$data } from '@components/data/import/__generated__/ImportFilesContentFileLine_file.graphql';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { Theme } from '../../../../components/Theme';
import { DataTableProps, DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import { defaultRender } from '../../../../components/dataGrid/dataTableUtils';
import { hexToRGB } from '../../../../utils/Colors';
import DataTableWithoutFragment from '../../../../components/dataGrid/DataTableWithoutFragment';
import { ImportWorksDrawerQuery, ImportWorksDrawerQuery$variables } from './__generated__/ImportWorksDrawerQuery.graphql';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import Transition from '../../../../components/Transition';
import useDraftContext from '../../../../utils/hooks/useDraftContext';

export const importConnectorsFragment = graphql`
  fragment ImportWorksDrawer_connectorsImport on Connector
  @relay(plural: true) {
    id
    name
    active
    only_contextual
    connector_scope
    updated_at
    configurations {
      id
      name,
      configuration
    }
  }
`;

export const fileWorksQuery = graphql`
  query ImportWorksDrawerQuery($filters: FilterGroup!) {
    connectorsForImport {
      id
      name
      active
      connector_scope
      updated_at
      configurations {
        id
        name,
        configuration
      }
    }
    importFiles(first: 500, filters: $filters) {
      edges {
        node {
          id
          works {
            id
            name
            connector {
              name
            }
            user {
              name
            }
            received_time
            tracking {
              import_expected_number
              import_processed_number
            }
            messages {
              timestamp
              message
            }
            errors {
              timestamp
              message
            }
            status
            timestamp
            draft_context
          }
        }
      }
    }
    pendingFiles(first: 500, filters: $filters) {
      edges {
        node {
          id
          works {
            id
            name
            connector {
              name
            }
            user {
              name
            }
            received_time
            tracking {
              import_expected_number
              import_processed_number
            }
            messages {
              timestamp
              message
            }
            errors {
              timestamp
              message
            }
            status
            timestamp
            draft_context
          }
        }
      }
    }
  }
`;

const importWorkDeleteMutation = graphql`
  mutation ImportWorksDrawerDeleteMutation($workId: ID!) {
    workEdit(id: $workId) {
      delete
    }
  }
`;

const LOCAL_STORAGE_KEY = 'file_works';

const FileWorksComponent = ({
  isWorkbench = false,
  queryRef,
  refetch,
}: {
  isWorkbench: boolean;
  queryRef: PreloadedQuery<ImportWorksDrawerQuery>;
  refetch: () => void;
}) => {
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery<ImportWorksDrawerQuery>(fileWorksQuery, queryRef);
  const draftContext = useDraftContext();
  const firstNode = !isWorkbench ? data.importFiles?.edges[0]?.node : data.pendingFiles?.edges[0]?.node;

  if (!firstNode) {
    return (<div>No Data</div>);
  }

  const { id, works } = firstNode;
  const [deleting, setDeleting] = useState(false);
  const [displayDelete, setDisplayDelete] = useState<string | undefined>();
  const localStorageKey = `${LOCAL_STORAGE_KEY}-${id}`;

  const deleteWork = (workId: string) => {
    commitMutation({
      ...defaultCommitMutation,
      mutation: importWorkDeleteMutation,
      variables: { workId },
      onCompleted: () => {
        setDeleting(false);
        setDisplayDelete(undefined);
        refetch();
      },
    });
  };

  const navigateToDraft = (draftId: string) => {
    navigate(`/dashboard/data/import/draft/${draftId}`);
  };
  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      id: 'Connector',
      label: 'Connector',
      percentWidth: 50,
      isSortable: false,
      render: ({ connector }) => defaultRender(connector.name),
    },
    timestamp: {
      id: 'Timestamp',
      label: 'Start time',
      percentWidth: 20,
      isSortable: false,
      render: ({ timestamp }, h) => defaultRender(h.nsdt(timestamp)),
    },
    tracking: {
      id: 'Tracking',
      label: 'tracking',
      percentWidth: 10,
      isSortable: false,
      render: ({ tracking }) => {
        return (
          <Chip
            label={`${tracking.import_processed_number || 0} / ${tracking.import_expected_number || 0}`}
            style={{
              fontSize: 12,
              height: 20,
              width: 90,
              borderRadius: 4,
            }}
          />
        );
      },
    },
    status: {
      id: 'Status',
      label: 'Status',
      percentWidth: 20,
      isSortable: false,
      render: ({ status, errors = [], messages = [] }, { nsdt }) => {
        const isError = errors.length > 0;
        const messagesAndErrors = [...messages, ...errors]
          .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

        const messageToDisplay = (
          <>
            {messagesAndErrors.length > 0 ? (
              messagesAndErrors.map((message) => (
                <div key={`${message.timestamp}-${message.message}`} style={{ minWidth: 200 }}>
                  [{nsdt(message.timestamp)}] {message.message}
                </div>
              ))
            ) : (
              t_i18n(status)
            )}
          </>
        );

        const color = useMemo(() => {
          if (isError) {
            return theme.palette.error.main;
          }
          if (status === 'progress' || status === 'wait') {
            return theme.palette.warn.main;
          }
          return theme.palette.success.main;
        }, [isError, status]);
        return (
          <Tooltip
            title={messageToDisplay}
            slotProps={{
              tooltip: {
                sx: {
                  maxWidth: 'none',
                  minWidth: '400px',
                  overflow: 'auto',
                },
              },
            }}
          >
            <Chip
              variant="outlined"
              label={isError ? t_i18n('Error') : t_i18n(status)}
              style={{
                fontSize: 12,
                lineHeight: '12px',
                height: 20,
                float: 'left',
                textTransform: 'uppercase',
                borderRadius: 4,
                width: 90,
                color,
                borderColor: color,
                backgroundColor: hexToRGB(color),
              }}
            />
          </Tooltip>
        );
      },
    },
  };

  return (
    <div>
      {works && works.length > 0 ? (
        <DataTableWithoutFragment
          dataColumns={dataColumns}
          data={works}
          storageKey={localStorageKey}
          isLocalStorageEnabled={false}
          globalCount={works.length}
          variant={DataTableVariant.inline}
          actions={(work: { id: string; draft_context?: string; status: string }) => (
            <div style={{ marginLeft: work?.draft_context && !draftContext ? -45 : 0 }}>
              {work?.draft_context && !draftContext && (
                <Tooltip title={t_i18n('Navigate to draft')}>
                  <IconButton
                    color="primary"
                    onClick={() => work.draft_context && navigateToDraft(work.draft_context)}
                  >
                    <ArchitectureOutlined fontSize="small" />
                  </IconButton>
                </Tooltip>
              )}

              <Tooltip title={t_i18n('Delete this work')}>
                <IconButton
                  disabled={work?.status === 'deleting'}
                  color="primary"
                  onClick={() => setDisplayDelete(work?.id)}
                >
                  <DeleteOutlined fontSize="small" />
                </IconButton>
              </Tooltip>
            </div>
          )}
          disableNavigation
        />
      ) : (
        <div style={{
          paddingBlock: 8,
          fontSize: 15,
        }}
        >
          {t_i18n('No import works for this file')}
        </div>

      )}
      {!!displayDelete && (
        <Dialog
          open={!!displayDelete}
          slotProps={{ paper: { elevation: 1 } }}
          slots={{ transition: Transition }}
          onClose={() => setDisplayDelete(undefined)}
        >
          <DialogContent>
            <DialogContentText>
              {t_i18n('Do you want to remove this job?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button variant="secondary" onClick={() => setDisplayDelete(undefined)}>
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={() => deleteWork(displayDelete)}
              disabled={deleting}
            >
              {t_i18n('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
      )}
    </div>
  );
};

const ImportWorksDrawer = ({
  open,
  onClose,
  file,
}: {
  open: DrawerProps['open'];
  onClose: () => void;
  file: ImportWorkbenchesContentFileLine_file$data | ImportFilesContentFileLine_file$data;
}) => {
  const { t_i18n } = useFormatter();
  const [openLaunchImport, setOpenLaunchImport] = useState(false);
  const [queryRef, loadQuery, disposeQuery] = useQueryLoader<ImportWorksDrawerQuery>(fileWorksQuery);
  const draftContext = useDraftContext();
  const paginationFilters = {
    filters: {
      mode: 'and',
      filters: [
        {
          key: 'name',
          operator: 'eq',
          values: [file.name],
          mode: 'or',
        },
      ],
      filterGroups: [],
    },
  } as unknown as ImportWorksDrawerQuery$variables;

  // Load query when drawer opens or file changes
  useEffect(() => {
    let intervalId: NodeJS.Timeout;

    const loadData = () => {
      loadQuery(paginationFilters, { fetchPolicy: 'store-and-network' });
    };

    if (open) {
      // Initial load
      loadData();

      // Set up interval for periodic refetching
      intervalId = setInterval(loadData, 5000); // 5 seconds
    }

    return () => {
      if (intervalId) clearInterval(intervalId);
      if (disposeQuery) disposeQuery();
    };
  }, [open, file.name, loadQuery, disposeQuery]);

  const handleRefetch = useCallback(() => {
    loadQuery(paginationFilters, { fetchPolicy: 'network-only' });
  }, [loadQuery, paginationFilters.filters]);

  const launchImportTitle = t_i18n('Launch an import');

  // Prevent launch import and change query on workbenches
  const isWorkbench = file.id.includes('import/pending');

  return (
    <>
      <Drawer
        title={t_i18n('File imports')}
        header={(
          <>
            {!isWorkbench && (
              <Button
                onClick={() => setOpenLaunchImport(true)}
                size="small"
                aria-label={launchImportTitle}
                title={launchImportTitle}
                sx={{ marginLeft: 'auto', marginRight: 2 }}
              >
                {launchImportTitle}
              </Button>
            )}
          </>
        )}
        open={open}
        onClose={onClose}
      >
        <>
          <Alert severity="info">{t_i18n('This page lists the most recent works.')}</Alert>
          {queryRef && (
            <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
              <FileWorksComponent
                isWorkbench={isWorkbench}
                queryRef={queryRef}
                refetch={handleRefetch}
              />
            </Suspense>
          )}
        </>
      </Drawer>
      {queryRef && openLaunchImport && (
        <LaunchImportDialog
          file={file}
          queryRef={queryRef}
          open={openLaunchImport}
          onClose={() => setOpenLaunchImport(false)}
          onSuccess={handleRefetch}
          isDraftContext={!!draftContext}
        />
      )}
    </>
  );
};

export default ImportWorksDrawer;
