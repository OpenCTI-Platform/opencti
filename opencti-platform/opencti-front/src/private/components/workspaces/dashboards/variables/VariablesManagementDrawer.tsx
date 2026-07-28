import React, { Suspense, useEffect, useMemo, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Switch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import AddOutlined from '@mui/icons-material/AddOutlined';
import DeleteOutlined from '@mui/icons-material/DeleteOutlined';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../../components/i18n';
import VariableDefinitionDialog from './VariableDefinitionDialog';
import Drawer from '../../../common/drawer/Drawer';
import type { VariablesManagementDrawerDefaultEntityLabelQuery } from './__generated__/VariablesManagementDrawerDefaultEntityLabelQuery.graphql';

const variableDeleteMutation = graphql`
  mutation VariablesManagementDrawerDeleteMutation($id: ID!, $variableId: ID!) {
    workspaceVariableDelete(id: $id, variableId: $variableId)
  }
`;

const variableSetValueMutation = graphql`
  mutation VariablesManagementDrawerSetValueMutation($workspaceId: ID!, $variableId: ID!, $value: String) {
    workspaceVariableSetValue(workspaceId: $workspaceId, variableId: $variableId, value: $value) {
      id
      variable_values
    }
  }
`;

const variableResetValueMutation = graphql`
  mutation VariablesManagementDrawerResetValueMutation($workspaceId: ID!, $variableId: ID!) {
    workspaceVariableResetValue(workspaceId: $workspaceId, variableId: $variableId) {
      id
      variable_values
    }
  }
`;

const defaultEntityLabelQuery = graphql`
  query VariablesManagementDrawerDefaultEntityLabelQuery($filters: FilterGroup!) {
    filtersRepresentatives(filters: $filters) {
      value
    }
  }
`;

const TYPE_LABELS: Record<string, string> = {
  entity_ref: 'Entity picker',
  boolean: 'Boolean',
  vocabulary: 'Vocabulary',
  numeric: 'Number',
  text: 'Text',
  kill_chain: 'Kill chain phase',
};

const EntityDefaultValueLabel: React.FC<{ entityId: string; fallback: string }> = ({ entityId, fallback }) => {
  const data = useLazyLoadQuery<VariablesManagementDrawerDefaultEntityLabelQuery>(
    defaultEntityLabelQuery,
    {
      filters: {
        mode: 'and',
        filters: [{ key: 'ids', values: [entityId], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
    },
    { fetchPolicy: 'store-or-network' },
  );
  return <>{data.filtersRepresentatives?.[0]?.value ?? fallback}</>;
};

interface Variable {
  readonly id: string;
  readonly name: string;
  readonly filterKey: string;
  readonly filterKeyType: string;
  readonly defaultValue?: string | null;
}

interface VariablesManagementDrawerProps {
  open: boolean;
  onClose: () => void;
  workspaceId: string;
  variables: ReadonlyArray<Variable>;
  userVariableValues?: string | null;
}

const VariablesManagementDrawer: React.FC<VariablesManagementDrawerProps> = ({
  open,
  onClose,
  workspaceId,
  variables,
  userVariableValues,
}) => {
  const { t_i18n } = useFormatter();
  const [commitDelete] = useApiMutation(variableDeleteMutation);
  const [commitSetValue] = useApiMutation(variableSetValueMutation);
  const [commitResetValue] = useApiMutation(variableResetValueMutation);
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [localVars, setLocalVars] = useState<Variable[]>([...variables]);
  const [enabledMap, setEnabledMap] = useState<Record<string, boolean>>({});
  const typeLabels = useMemo(() => TYPE_LABELS, []);
  const ENABLED_PREFIX = '__enabled__:';

  const getIsEnabled = (variableId: string, source: Record<string, unknown>) => source[`${ENABLED_PREFIX}${variableId}`] !== 'false';

  useEffect(() => {
    setLocalVars([...variables]);
  }, [variables]);

  useEffect(() => {
    let parsedValues: Record<string, unknown> = {};
    try {
      parsedValues = userVariableValues ? JSON.parse(userVariableValues) as Record<string, unknown> : {};
    } catch {
      parsedValues = {};
    }
    setEnabledMap(
      Object.fromEntries(variables.map((variable) => [variable.id, getIsEnabled(variable.id, parsedValues)])),
    );
  }, [userVariableValues, variables]);

  const handleDelete = (variableId: string) => {
    commitDelete({
      variables: { id: workspaceId, variableId },
      updater: (store) => {
        const workspaceRecord = store.get(workspaceId);
        if (!workspaceRecord) {
          return;
        }
        const currentVariables = workspaceRecord.getLinkedRecords('variables') ?? [];
        const nextVariables = currentVariables.filter((variableRecord) => variableRecord.getDataID() !== variableId);
        workspaceRecord.setLinkedRecords(nextVariables, 'variables');
      },
      onCompleted: () => {
        setLocalVars((prev) => prev.filter((v) => v.id !== variableId));
      },
    });
  };

  const handleToggleVariable = (variableId: string, enabled: boolean) => {
    setEnabledMap((prev) => ({ ...prev, [variableId]: enabled }));
    const stateKey = `${ENABLED_PREFIX}${variableId}`;
    if (enabled) {
      commitResetValue({
        variables: { workspaceId, variableId: stateKey },
      });
      return;
    }
    commitSetValue({
      variables: { workspaceId, variableId: stateKey, value: 'false' },
    });
  };

  return (
    <>
      <Drawer
        open={open}
        onClose={onClose}
        title={t_i18n('Dashboard variables')}
        size="medium"
        header={(
          <Button
            startIcon={<AddOutlined />}
            variant="contained"
            size="small"
            onClick={() => setAddDialogOpen(true)}
          >
            {t_i18n('Create variable')}
          </Button>
        )}
      >
        <Box sx={{ overflow: 'auto', flexGrow: 1, mx: -3 }}>
          {localVars.length === 0 ? (
            <Box sx={{ p: 4, textAlign: 'center' }}>
              <Typography variant="body2" color="text.secondary">
                {t_i18n('No variables defined yet. Add one to get started.')}
              </Typography>
            </Box>
          ) : (
            <List sx={{ p: 0 }}>
              {localVars.map((variable) => (
                <ListItem
                  key={variable.id}
                  divider
                  sx={{
                    alignItems: 'flex-start',
                    px: 3,
                    py: 2,
                    borderColor: 'divider',
                  }}
                >
                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    <Typography variant="body2" color="text.secondary">
                      {t_i18n('Variable name')}
                    </Typography>
                    <Typography variant="body1" fontWeight="medium" sx={{ mb: 1.5 }}>
                      {variable.name}
                    </Typography>

                    <Typography variant="body2" color="text.secondary">
                      {t_i18n('Variable type')}
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 1.5 }}>
                      {t_i18n(typeLabels[variable.filterKeyType] ?? variable.filterKeyType)}
                    </Typography>

                    <FormControlLabel
                      sx={{ mb: 1 }}
                      control={(
                        <Switch
                          size="small"
                          checked={enabledMap[variable.id] ?? true}
                          onChange={(_event, checked) => handleToggleVariable(variable.id, checked)}
                        />
                      )}
                      label={t_i18n('Use variable')}
                    />

                    <Typography variant="body2" color="text.secondary">
                      {t_i18n('Default value')}
                    </Typography>
                    <Typography variant="body2">
                      {variable.defaultValue
                        ? (
                            variable.filterKeyType === 'entity_ref'
                              ? (
                                  <Suspense fallback={<>{variable.defaultValue}</>}>
                                    <EntityDefaultValueLabel entityId={variable.defaultValue} fallback={variable.defaultValue} />
                                  </Suspense>
                                )
                              : variable.defaultValue
                          )
                        : t_i18n('(not set)')}
                    </Typography>
                  </Box>
                  <Box sx={{ ml: 2, pt: 0.5 }}>
                    <Tooltip title={t_i18n('Delete variable')}>
                      <IconButton
                        edge="end"
                        size="small"
                        onClick={() => handleDelete(variable.id)}
                        color="error"
                      >
                        <DeleteOutlined fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </Box>
                </ListItem>
              ))}
            </List>
          )}
        </Box>
      </Drawer>
      <VariableDefinitionDialog
        open={addDialogOpen}
        workspaceId={workspaceId}
        onClose={() => setAddDialogOpen(false)}
      />
    </>
  );
};

export default VariablesManagementDrawer;
