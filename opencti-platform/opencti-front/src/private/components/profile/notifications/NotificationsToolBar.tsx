import React, { FunctionComponent, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { graphql } from 'react-relay';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import Table from '@mui/material/Table';
import TableHead from '@mui/material/TableHead';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableRow from '@mui/material/TableRow';
import IconButton from '@mui/material/IconButton';
import { CheckCircleOutlined, ClearOutlined, DeleteOutlined, UnpublishedOutlined } from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import DialogTitle from '@mui/material/DialogTitle';
import Alert from '@mui/material/Alert';
import makeStyles from '@mui/styles/makeStyles';
import { truncate } from '../../../../utils/String';
import { MESSAGING$ } from '../../../../relay/environment';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { NotificationLine_node$data } from './__generated__/NotificationLine_node.graphql';
import Transition from '../../../../components/Transition';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import TasksFilterValueContainer from '../../../../components/TasksFilterValueContainer';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  bottomNav: {
    padding: 0,
    zIndex: 1,
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
  title: {
    flex: '1 1 100%',
    fontSize: '12px',
  },
  selectedElementsNumber: {
    padding: '2px 5px 2px 5px',
    marginRight: 5,
    backgroundColor: theme.palette.secondary.main,
    color: '#ffffff',
  },
  filtersNumber: {
    padding: '2px 5px 2px 5px',
    marginRight: 5,
    color: theme.palette.mode === 'dark' ? '#000000' : '#ffffff',
    backgroundColor: theme.palette.primary.main,
  },
}));

const notificationsToolBarListTaskAddMutation = graphql`
  mutation NotificationsToolBarListTaskAddMutation($input: ListTaskAddInput!) {
    listTaskAdd(input: $input) {
      id
      type
    }
  }
`;

const notificationsToolBarQueryTaskAddMutation = graphql`
  mutation NotificationsToolBarQueryTaskAddMutation(
    $input: QueryTaskAddInput!
  ) {
    queryTaskAdd(input: $input) {
      id
      type
    }
  }
`;

interface NotificationsToolBarProps {
  numberOfSelectedElements: number;
  handleClearSelectedElements: () => void;
  selectedElements: Record<string, NotificationLine_node$data>;
  deSelectedElements: Record<string, NotificationLine_node$data>;
  selectAll: boolean;
  filters: FilterGroup;
}

const NotificationsToolBar: FunctionComponent<NotificationsToolBarProps> = ({
  numberOfSelectedElements,
  handleClearSelectedElements,
  selectedElements,
  deSelectedElements,
  selectAll,
  filters,
}) => {
  const classes = useStyles();
  const { t_i18n, n } = useFormatter();

  const isOpen = numberOfSelectedElements > 0;

  const [commitQueryTask] = useApiMutation(
    notificationsToolBarQueryTaskAddMutation,
  );
  const [commitListTask] = useApiMutation(notificationsToolBarListTaskAddMutation);

  const [displayTask, setDisplayTask] = useState(false);
  const [actions, setActions] = useState<
  {
    type: string;
    context: null | {
      field: string;
      type: string;
      values:(string | { id: string; value: string })[];
    };
  }[]
  >([]);
  const [processing, setProcessing] = useState(false);
  const [navOpen, setNavOpen] = useState(
    localStorage.getItem('navOpen') === 'true',
  );

  useEffect(() => {
    const subscription = MESSAGING$.toggleNav.subscribe({
      next: () => setNavOpen(localStorage.getItem('navOpen') === 'true'),
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  });

  const handleOpenTask = () => {
    setDisplayTask(true);
  };

  const handleCloseTask = () => {
    setDisplayTask(false);
    setActions([]);
    setProcessing(false);
  };

  const handleLaunchRead = (read: boolean) => {
    setActions([
      {
        type: 'REPLACE',
        context: {
          field: 'is_read',
          type: 'ATTRIBUTE',
          values: [read ? 'true' : 'false'],
        },
      },
    ]);
    handleOpenTask();
  };

  const handleLaunchDelete = () => {
    setActions([{ type: 'DELETE', context: null }]);
    handleOpenTask();
  };
  const onSubmitCompleted = () => {
    handleClearSelectedElements();
    MESSAGING$.notifySuccess(
      <span>
        {t_i18n('The background task has been executed. You can monitor it on')}{' '}
        <Link to="/dashboard/data/processing/tasks">{t_i18n('the dedicated page')}</Link>.
      </span>,
    );
    setProcessing(false);
    handleCloseTask();
  };
  const submitTask = () => {
    setProcessing(true);
    if (numberOfSelectedElements === 0) return;
    const jsonFilters = serializeFilterGroupForBackend(filters);
    const finalActions = actions.map((action) => ({
      type: action.type,
      context: action.context
        ? {
          ...action.context,
          values: action.context.values,
        }
        : null,
    }));
    if (selectAll) {
      commitQueryTask({
        variables: {
          input: {
            filters: jsonFilters,
            actions: finalActions,
            excluded_ids: Object.keys(deSelectedElements || {}),
            scope: 'USER',
          },
        },
        onCompleted: () => {
          onSubmitCompleted();
        },
      });
    } else {
      commitListTask({
        variables: {
          input: {
            ids: Object.keys(selectedElements),
            actions: finalActions,
            scope: 'USER',
          },
        },
        onCompleted: () => {
          onSubmitCompleted();
        },
      });
    }
  };

  return (
    <UserContext.Consumer>
      {({ bannerSettings }) => (
        <Drawer
          anchor="bottom"
          variant="persistent"
          classes={{ paper: classes.bottomNav }}
          open={isOpen}
          PaperProps={{
            variant: 'elevation',
            elevation: 1,
            style: {
              paddingLeft: navOpen ? 185 : 60,
              bottom: bannerSettings?.bannerHeightNumber ?? 0,
            },
          }}
        >
          <Toolbar style={{ minHeight: 54 }}>
            <Typography
              className={classes.title}
              color="inherit"
              variant="subtitle1"
            >
              <span className={classes.selectedElementsNumber}>
                {numberOfSelectedElements}
              </span>{' '}
              {t_i18n('selected')}{' '}
              <IconButton
                aria-label="clear"
                disabled={numberOfSelectedElements === 0 || processing}
                onClick={handleClearSelectedElements}
                size="small"
              >
                <ClearOutlined fontSize="small" />
              </IconButton>
            </Typography>
            <Tooltip title={t_i18n('Mark as read')}>
              <span>
                <IconButton
                  aria-label="ack"
                  disabled={numberOfSelectedElements === 0 || processing}
                  onClick={() => handleLaunchRead(true)}
                  color="success"
                  size="small"
                >
                  <CheckCircleOutlined fontSize="small" />
                </IconButton>
              </span>
            </Tooltip>
            <Tooltip title={t_i18n('Mark as unread')}>
              <span>
                <IconButton
                  aria-label="ack"
                  disabled={numberOfSelectedElements === 0 || processing}
                  onClick={() => handleLaunchRead(false)}
                  color="warning"
                  size="small"
                >
                  <UnpublishedOutlined fontSize="small" />
                </IconButton>
              </span>
            </Tooltip>
            <Tooltip title={t_i18n('Delete')}>
              <span>
                <IconButton
                  aria-label="delete"
                  disabled={numberOfSelectedElements === 0 || processing}
                  onClick={handleLaunchDelete}
                  color="primary"
                  size="small"
                >
                  <DeleteOutlined fontSize="small" />
                </IconButton>
              </span>
            </Tooltip>
          </Toolbar>
          <Dialog
            PaperProps={{ elevation: 1 }}
            open={displayTask}
            keepMounted={true}
            TransitionComponent={Transition}
            onClose={handleCloseTask}
            fullWidth={true}
            maxWidth="md"
          >
            <DialogTitle>
              <div style={{ float: 'left' }}>
                {t_i18n('Launch a background task')}
              </div>
              <div style={{ float: 'right' }}>
                <span className={classes.selectedElementsNumber}>
                  {n(numberOfSelectedElements)}
                </span>{' '}
                {t_i18n('selected element(s)')}
              </div>
            </DialogTitle>
            <DialogContent>
              {numberOfSelectedElements > 1000 && (
                <Alert severity="warning">
                  {t_i18n(
                    "You're targeting more than 1000 entities with this background task, be sure of what you're doing!",
                  )}
                </Alert>
              )}
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>#</TableCell>
                      <TableCell>{t_i18n('Step')}</TableCell>
                      <TableCell>{t_i18n('Field')}</TableCell>
                      <TableCell>{t_i18n('Values')}</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    <TableRow>
                      <TableCell>
                        {' '}
                        <span className={classes.filtersNumber}>1</span>
                      </TableCell>
                      <TableCell>
                        <Chip label="SCOPE" />
                      </TableCell>
                      <TableCell>{t_i18n('N/A')}</TableCell>
                      <TableCell>
                        {selectAll ? (
                          <TasksFilterValueContainer
                            filters={filters}
                            entityTypes={['Notification']}
                          />
                        ) : (
                          <span>
                            {truncate(
                              Object.values(selectedElements || {})
                                .map((o) => getMainRepresentative(o))
                                .join(', '),
                              80,
                            )}
                          </span>
                        )}
                      </TableCell>
                    </TableRow>
                    {actions.map((o) => {
                      const number = actions.indexOf(o);
                      return (
                        <TableRow key={o.type}>
                          <TableCell>
                            {' '}
                            <span className={classes.filtersNumber}>
                              {number + 2}
                            </span>
                          </TableCell>
                          <TableCell>
                            <Chip label={o.type} />
                          </TableCell>
                          <TableCell>{o.context?.field ?? t_i18n('N/A')}</TableCell>
                          <TableCell>
                            {truncate(
                              (o.context?.values ?? [])
                                .map((p) => (typeof p === 'string' ? p : getMainRepresentative(p)))
                                .join(', '),
                              80,
                            )}
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </TableContainer>
            </DialogContent>
            <DialogActions>
              <Button onClick={handleCloseTask} disabled={processing}>
                {t_i18n('Cancel')}
              </Button>
              <Button
                onClick={submitTask}
                color="secondary"
                disabled={processing}
              >
                {t_i18n('Launch')}
              </Button>
            </DialogActions>
          </Dialog>
        </Drawer>
      )}
    </UserContext.Consumer>
  );
};

export default NotificationsToolBar;
