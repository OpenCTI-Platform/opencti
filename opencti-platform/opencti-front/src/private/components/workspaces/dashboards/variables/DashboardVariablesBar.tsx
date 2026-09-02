import React, { useEffect, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Stack from '@mui/material/Stack';
import VariableValueControl from './VariableValueControl';
import PresetSelectorDropdown from './PresetSelectorDropdown';
import type { DashboardConfig } from '../../../../../components/dashboard/dashboard-types';
import { useDashboardVariables } from './DashboardVariablesContext';
import type { DashboardVariablesBar_workspace$key } from './__generated__/DashboardVariablesBar_workspace.graphql';

const variablesBarFragment = graphql`
  fragment DashboardVariablesBar_workspace on Workspace {
    id
    variables {
      id
      name
      filterKey
      filterKeyType
      defaultValue
      restrictionMode
      restrictionValues
      restrictionFilters
    }
    ...PresetSelectorDropdown_workspace
  }
`;

interface DashboardVariablesBarProps {
  data: DashboardVariablesBar_workspace$key;
  /** Serialised JSON state for this user's runtime values, from WorkspaceUserState */
  userVariableValues?: string | null;
  timeConfig?: DashboardConfig;
  onApplyPresetTime?: (timeConfig: {
    startDate: string | null;
    endDate: string | null;
    relativeDate: string | null;
  }) => void;
  usedVariableIds?: string[];
  canEditStructure: boolean;
  canSwitchValues: boolean;
}

const DashboardVariablesBar: React.FC<DashboardVariablesBarProps> = ({
  data,
  userVariableValues,
  timeConfig,
  onApplyPresetTime,
  usedVariableIds = [],
  canEditStructure,
  canSwitchValues,
}) => {
  const workspace = useFragment(variablesBarFragment, data);
  const [localVariables, setLocalVariables] = useState([...workspace.variables]);
  const { variableValues } = useDashboardVariables();

  useEffect(() => {
    setLocalVariables([...workspace.variables]);
  }, [workspace.variables]);

  const usedVariablesSet = new Set(usedVariableIds);

  const handleVariableDeleted = (deletedVariableId: string) => {
    setLocalVariables((prev) => prev.filter((v) => v.id !== deletedVariableId));
  };

  const variables = localVariables;

  if (!canSwitchValues && variables.length === 0) return null;

  return (
    <>
      <Stack direction="row" alignItems="center" flexWrap="wrap" gap={0.5} sx={{ px: 0.5 }}>
        {variables.map((variable) => (
          <VariableValueControl
            key={variable.id}
            workspaceId={workspace.id}
            variableId={variable.id}
            variableName={variable.name}
            filterKey={variable.filterKey ?? undefined}
            filterKeyType={variable.filterKeyType}
            isUsedInWidgets={usedVariablesSet.has(variable.id)}
            currentValue={variableValues[variable.id] ?? null}
            defaultValue={variable.defaultValue ?? null}
            restrictionMode={variable.restrictionMode}
            restrictionValues={variable.restrictionValues}
            restrictionFilters={variable.restrictionFilters}
            onVariableDeleted={handleVariableDeleted}
          />
        ))}
        <PresetSelectorDropdown
          data={workspace}
          currentTimeConfig={timeConfig}
          onApplyPresetTime={onApplyPresetTime}
          canEditStructure={canEditStructure}
        />
      </Stack>
    </>
  );
};

export default DashboardVariablesBar;
