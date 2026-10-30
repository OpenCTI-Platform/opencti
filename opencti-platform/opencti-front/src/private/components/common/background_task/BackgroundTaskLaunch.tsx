import * as R from 'ramda';
import { graphql } from 'react-relay';
import { Link } from 'react-router';
import { useTheme } from '@mui/material/styles';
import { Alert, Button, Chip } from '@filigran/design-system';
import { Box, DialogActions, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from '@mui/material';
import Dialog from '../../../../components/common/dialog/Dialog';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import TasksFilterValueContainer from '../../../../components/TasksFilterValueContainer';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { truncate } from '../../../../utils/String';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import useAuth from '../../../../utils/hooks/useAuth';
import { removeIdAndIncorrectKeysFromFilterGroupObject, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { BackgroundTaskLaunchListTaskAddMutation } from './__generated__/BackgroundTaskLaunchListTaskAddMutation.graphql';
import {
  BackgroundTaskLaunchQueryTaskAddMutation,
  BackgroundTaskScope,
  BackgroundTaskActionInput,
  BackgroundTaskActionType,
} from './__generated__/BackgroundTaskLaunchQueryTaskAddMutation.graphql';

const listTaskAddMutation = graphql`
  mutation BackgroundTaskLaunchListTaskAddMutation($input: ListTaskAddInput!) {
    listTaskAdd(input: $input) {
      id
      type
    }
  }
`;

const queryTaskAddMutation = graphql`
  mutation BackgroundTaskLaunchQueryTaskAddMutation($input: QueryTaskAddInput!) {
    queryTaskAdd(input: $input) {
      id
      type
    }
  }
`;

const MAX_ENTITIES = 1000;

interface BackgroundTaskLaunchProps {
  display: boolean;
  onClose: () => void;
  onLaunch: () => void;
  onCompleted: () => void;
  numberOfSelectedElements: number;
  selectedElements: Record<string, unknown>;
  processing: boolean;
  taskScope: BackgroundTaskScope;
  actions: {
    type: BackgroundTaskActionType;
    context?: {
      field?: string;
      values?: ({ id?: string; value?: string } | string)[];
      options?: {
        includeNeighbours?: boolean;
        investigationId?: string;
      };
    };
  }[];
  selectAll?: boolean;
  description?: string;
  filters?: FilterGroup;
  search?: string;
  entityTypes?: string[];
  mergingElement?: { id: string };
  containerId?: string;
  promoteToContainer?: boolean;
  excludedIds?: string[];
  // To show the label of a custom field updated by an action, instead of its name
  customFieldDefinitions?: ReadonlyArray<{ name: string; label: string }>;
}

const BackgroundTaskLaunch = ({
  display,
  search,
  filters,
  onClose,
  onLaunch,
  onCompleted,
  selectAll,
  numberOfSelectedElements,
  entityTypes,
  processing,
  mergingElement,
  selectedElements,
  taskScope,
  actions,
  containerId,
  description,
  promoteToContainer,
  excludedIds,
  customFieldDefinitions,
}: BackgroundTaskLaunchProps) => {
  const { me, schema } = useAuth();
  const isInDraft = me.draftContext;

  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();

  const monitoringLink = !isInDraft
    ? <Link to="/dashboard/data/processing/tasks">{t_i18n('the dedicated page')}</Link>
    : t_i18n('the draft processes tab');
  const successMessage = (
    <span>
      {t_i18n('The background task has been executed. You can monitor it on')}{' '}
      {monitoringLink}
    </span>
  );

  const [listMutation] = useApiMutation<BackgroundTaskLaunchListTaskAddMutation>(
    listTaskAddMutation,
    undefined,
    { successMessage },
  );
  const [queryMutation] = useApiMutation<BackgroundTaskLaunchQueryTaskAddMutation>(
    queryTaskAddMutation,
    undefined,
    { successMessage },
  );

  const selectedElementsList = Object.values(selectedElements || {});
  const filterKeysMap = new Map();
  (entityTypes ?? []).forEach((entityType) => {
    const currentMap = schema.filterKeysSchema.get(entityType);
    currentMap?.forEach((value, key) => filterKeysMap.set(key, value));
  });
  const availableFilterKeys = Array.from(filterKeysMap.keys()).concat(['entity_type']);

  const displayActionValue = (element: unknown) => {
    if (typeof element === 'string') return element;
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    if (typeof element?.toISOString === 'function') return element.toISOString();
    return getMainRepresentative(element);
  };

  const getActionType = (type: BackgroundTaskActionType, field?: string) => {
    if (type === 'ADD' && field === 'groups') return 'ADD_GROUPS';
    if (type === 'ADD' && field === 'organizations') return 'ADD_ORGANIZATIONS';
    if (type === 'REMOVE' && field === 'groups') return 'REMOVE_GROUPS';
    if (type === 'REMOVE' && field === 'organizations') return 'REMOVE_ORGANIZATIONS';
    return type;
  };

  const normalizeActionValue = (element?: { id?: string; value?: string } | string) => {
    if (typeof element === 'string') return element;
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    if (typeof element?.toISOString === 'function') return element.toISOString();
    if (element?.id) return element.id;
    if (element?.value) return element.value;
    return element;
  };

  const getUserFinalActions = (): BackgroundTaskActionInput[] => {
    return actions.map((action) => {
      const currentType = getActionType(action.type, action.context?.field);
      return {
        type: currentType,
        context: {
          ...(action.context ?? {}),
          values: action.context?.values?.map((el) => normalizeActionValue(el)) ?? [],
        },
        containerId: null,
      };
    });
  };

  const getOtherActions = (): BackgroundTaskActionInput[] => {
    return actions.map(
      (action) => ({
        type: action.type,
        context: action.context
          ? {
              ...action.context,
              values: action.context.values?.map((el) => normalizeActionValue(el)) ?? [],
            }
          : null,
        containerId: action.type === 'PROMOTE' && promoteToContainer && containerId ? containerId : null,
      }),
    );
  };

  const launchTask = () => {
    onLaunch();
    const scope = taskScope ?? 'KNOWLEDGE';
    if (numberOfSelectedElements === 0) return;
    const jsonFilters = serializeFilterGroupForBackend(
      removeIdAndIncorrectKeysFromFilterGroupObject(filters, availableFilterKeys),
    );
    const finalActions = taskScope === 'USER'
      ? getUserFinalActions()
      : getOtherActions();

    if (selectAll) {
      queryMutation({
        variables: {
          input: {
            description,
            filters: jsonFilters,
            search,
            actions: finalActions,
            excluded_ids: excludedIds,
            scope,
          },
        },
        onCompleted,
      });
    } else {
      listMutation({
        variables: {
          input: {
            description,
            ids: mergingElement
              ? [mergingElement.id]
              : Object.keys(selectedElements),
            actions: finalActions,
            scope,
          },
        },
        onCompleted,
      });
    }
  };

  return (
    <Dialog
      open={display}
      onClose={onClose}
      data-testid="background-task-popup"
      title={(
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
          <span>{t_i18n('Launch a background task')}</span>
          <Typography variant="body1" color="textSecondary">
            {`${n(numberOfSelectedElements)} ${t_i18n('selected element(s)')}`}
          </Typography>
        </Box>
      )}
    >
      {numberOfSelectedElements > MAX_ENTITIES && (
        <Alert
          severity="warning"
          title={t_i18n('You\'re targeting more than 1000 entities with this background task, be sure of what you\'re doing!')}
        />
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
                <span
                  style={{
                    marginRight: 5,
                    padding: '2px 5px 2px 5px',
                    backgroundColor: theme.palette.primary.main,
                    color: theme.palette.mode === 'dark' ? '#000000' : '#ffffff',
                  }}
                >
                  1
                </span>
              </TableCell>
              <TableCell>
                <Chip label="SCOPE" />
              </TableCell>
              <TableCell>{t_i18n('N/A')}</TableCell>
              <TableCell>
                {selectAll ? (
                  <div>
                    {search && search.length > 0 && (
                      <span>
                        <Chip
                          className="my-1 mr-2"
                          label={`${t_i18n('Search')}: ${search}`}
                        />
                        {(filters?.filters?.length ?? 0) > 0 && (
                          <Chip label={t_i18n('and')} />
                        )}
                      </span>
                    )}
                    {filters && (
                      <TasksFilterValueContainer
                        filters={filters}
                        entityTypes={entityTypes}
                      />
                    )}
                  </div>
                ) : (
                  <span>
                    {mergingElement
                      ? truncate(getMainRepresentative(mergingElement), 80)
                      : truncate(selectedElementsList.map((o) => getMainRepresentative(o)).join(', '), 80)
                    }
                  </span>
                )}
              </TableCell>
            </TableRow>
            {actions.map((action, index) => (
              <TableRow key={action.type}>
                <TableCell>
                  {' '}
                  <span
                    style={{
                      marginRight: 5,
                      padding: '2px 5px 2px 5px',
                      backgroundColor: theme.palette.primary.main,
                      color: theme.palette.mode === 'dark' ? '#000000' : '#ffffff',
                    }}
                  >
                    {index + 2}
                  </span>
                </TableCell>
                <TableCell>
                  <Chip label={action.type} />
                </TableCell>
                <TableCell>
                  {customFieldDefinitions?.find((d) => d.name === action.context?.field)?.label
                    ?? R.pathOr(t_i18n('N/A'), ['context', 'field'], action)}
                </TableCell>
                <TableCell>
                  {truncate(
                    R.join(', ', R.pathOr([], ['context', 'values'], action).map(displayActionValue)),
                    80,
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
      <DialogActions>
        <Button
          priority="secondary"
          onClick={onClose}
          disabled={processing}
        >
          {t_i18n('Cancel')}
        </Button>
        <Button
          onClick={launchTask}
          disabled={processing}
        >
          {t_i18n('Launch')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default BackgroundTaskLaunch;
