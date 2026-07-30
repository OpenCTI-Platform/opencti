import React, { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Button from '@mui/material/Button';
import MenuItem from '@mui/material/MenuItem';
import Menu from '@mui/material/Menu';
import ListItemText from '@mui/material/ListItemText';
import Tooltip from '@mui/material/Tooltip';
import IconButtonMui from '@mui/material/IconButton';
import IconButton from '@common/button/IconButton';
import BookmarkBorderOutlined from '@mui/icons-material/BookmarkBorderOutlined';
import SaveOutlined from '@mui/icons-material/SaveOutlined';
import ExpandMoreOutlined from '@mui/icons-material/ExpandMoreOutlined';
import DeleteOutlined from '@mui/icons-material/DeleteOutlined';
import Box from '@mui/material/Box';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../../components/i18n';
import PresetManagementDialog from './PresetManagementDialog';
import type { DashboardConfig } from '../../../../../components/dashboard/dashboard-types';
import { useDashboardVariables } from './DashboardVariablesContext';
import type { PresetSelectorDropdown_workspace$key } from './__generated__/PresetSelectorDropdown_workspace.graphql';

const presetSelectorFragment = graphql`
  fragment PresetSelectorDropdown_workspace on Workspace {
    id
    presets {
      id
      name
      variable_values
    }
    ...PresetManagementDialog_workspace
  }
`;

const presetApplyMutation = graphql`
  mutation PresetSelectorDropdownApplyMutation($workspaceId: ID!, $presetId: ID!) {
    workspacePresetApply(workspaceId: $workspaceId, presetId: $presetId) {
      id
      variable_values
    }
  }
`;

const presetDeleteMutation = graphql`
  mutation PresetSelectorDropdownDeleteMutation($id: ID!, $presetId: ID!) {
    workspacePresetDelete(id: $id, presetId: $presetId)
  }
`;

interface PresetSelectorDropdownProps {
  data: PresetSelectorDropdown_workspace$key;
  currentTimeConfig?: DashboardConfig;
  onApplyPresetTime?: (timeConfig: {
    startDate: string | null;
    endDate: string | null;
    relativeDate: string | null;
  }) => void;
  canEditStructure: boolean;
}

const PresetSelectorDropdown: React.FC<PresetSelectorDropdownProps> = ({
  data,
  currentTimeConfig,
  onApplyPresetTime,
  canEditStructure,
}) => {
  const { t_i18n } = useFormatter();
  const { setVariableValues } = useDashboardVariables();
  const workspace = useFragment(presetSelectorFragment, data);
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [saveOpen, setSaveOpen] = useState(false);
  const [commitApply] = useApiMutation(presetApplyMutation);
  const [commitDelete] = useApiMutation(presetDeleteMutation);

  const PRESET_START_DATE_KEY = '__preset_startDate';
  const PRESET_END_DATE_KEY = '__preset_endDate';
  const PRESET_RELATIVE_DATE_KEY = '__preset_relativeDate';

  const readTimeFromPreset = (variableValues: string) => {
    try {
      const parsed = JSON.parse(variableValues) as Record<string, unknown>;
      return {
        startDate: typeof parsed[PRESET_START_DATE_KEY] === 'string' ? parsed[PRESET_START_DATE_KEY] : null,
        endDate: typeof parsed[PRESET_END_DATE_KEY] === 'string' ? parsed[PRESET_END_DATE_KEY] : null,
        relativeDate: typeof parsed[PRESET_RELATIVE_DATE_KEY] === 'string' ? parsed[PRESET_RELATIVE_DATE_KEY] : null,
      };
    } catch {
      return {
        startDate: null,
        endDate: null,
        relativeDate: null,
      };
    }
  };

  const handleApply = (presetId: string) => {
    const preset = workspace.presets.find((p) => p.id === presetId);
    if (preset && onApplyPresetTime) {
      onApplyPresetTime(readTimeFromPreset(preset.variable_values));
    }
    commitApply({
      variables: { workspaceId: workspace.id, presetId },
      onCompleted: (response) => {
        const rawValues = response?.workspacePresetApply?.variable_values;
        if (!rawValues) {
          return;
        }
        try {
          const parsed = JSON.parse(rawValues) as Record<string, unknown>;
          const nextVariableValues = Object.fromEntries(
            Object.entries(parsed).filter(([key, value]) => !key.startsWith('__preset_') && typeof value === 'string'),
          ) as Record<string, string>;
          setVariableValues(nextVariableValues);
        } catch {
          setVariableValues({});
        }
      },
    });
    setAnchorEl(null);
  };

  const handleDeletePreset = (event: React.MouseEvent, presetId: string) => {
    event.preventDefault();
    event.stopPropagation();
    commitDelete({
      variables: { id: workspace.id, presetId },
      updater: (store) => {
        const workspaceRecord = store.get(workspace.id);
        if (!workspaceRecord) {
          return;
        }
        const currentPresets = workspaceRecord.getLinkedRecords('presets') ?? [];
        const nextPresets = currentPresets.filter((presetRecord) => presetRecord.getDataID() !== presetId);
        workspaceRecord.setLinkedRecords(nextPresets, 'presets');
      },
    });
  };

  if (workspace.presets.length === 0 && !canEditStructure) return null;

  return (
    <>
      <Box sx={{ display: 'inline-flex', alignItems: 'center', gap: 0.5 }}>
        <Button
          size="small"
          startIcon={<BookmarkBorderOutlined />}
          endIcon={<ExpandMoreOutlined />}
          onClick={(e) => setAnchorEl(e.currentTarget)}
          variant="outlined"
        >
          {t_i18n('Presets')}
        </Button>
        {canEditStructure && (
          <Tooltip title={t_i18n('Save preset')}>
            <IconButton color="primary" onClick={() => setSaveOpen(true)}>
              <SaveOutlined fontSize="small" />
            </IconButton>
          </Tooltip>
        )}
      </Box>

      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={() => setAnchorEl(null)}>
        {workspace.presets.length === 0 && (
          <MenuItem disabled>
            <ListItemText secondary={t_i18n('No presets available')} />
          </MenuItem>
        )}
        {workspace.presets.map((preset) => (
          <MenuItem key={preset.id} onClick={() => handleApply(preset.id)}>
            <ListItemText primary={preset.name} />
            {canEditStructure && (
              <Tooltip title={t_i18n('Delete preset')}>
                <IconButtonMui
                  edge="end"
                  size="small"
                  color="error"
                  onClick={(event) => handleDeletePreset(event, preset.id)}
                >
                  <DeleteOutlined fontSize="small" />
                </IconButtonMui>
              </Tooltip>
            )}
          </MenuItem>
        ))}
      </Menu>

      {canEditStructure && (
        <PresetManagementDialog
          open={saveOpen}
          data={workspace}
          currentTimeConfig={currentTimeConfig}
          onClose={() => setSaveOpen(false)}
        />
      )}
    </>
  );
};

export default PresetSelectorDropdown;
