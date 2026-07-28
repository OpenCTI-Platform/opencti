import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import { useFormik } from 'formik';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../../components/i18n';
import type { DashboardConfig } from '../../../../../components/dashboard/dashboard-types';
import { useDashboardVariables } from './DashboardVariablesContext';
import type { PresetManagementDialog_workspace$key } from './__generated__/PresetManagementDialog_workspace.graphql';

const presetManagementFragment = graphql`
  fragment PresetManagementDialog_workspace on Workspace {
    id
  }
`;

const presetAddMutation = graphql`
  mutation PresetManagementDialogAddMutation($id: ID!, $input: DashboardPresetInput!) {
    workspacePresetAdd(id: $id, input: $input) {
      id
      manifest
      presets {
        id
        name
        variable_values
      }
    }
  }
`;

const PRESET_START_DATE_KEY = '__preset_startDate';
const PRESET_END_DATE_KEY = '__preset_endDate';
const PRESET_RELATIVE_DATE_KEY = '__preset_relativeDate';
const ENABLED_PREFIX = '__enabled__:';

interface PresetManagementDialogProps {
  open: boolean;
  data: PresetManagementDialog_workspace$key;
  currentTimeConfig?: DashboardConfig;
  onClose: () => void;
}

const PresetManagementDialog: React.FC<PresetManagementDialogProps> = ({
  open,
  data,
  currentTimeConfig,
  onClose,
}) => {
  const { t_i18n } = useFormatter();
  const { rawVariableValues } = useDashboardVariables();
  const workspace = useFragment(presetManagementFragment, data);
  const [commitAdd] = useApiMutation(presetAddMutation);

  const buildPresetPayload = () => {
    const rawValues = rawVariableValues as Record<string, unknown>;

    const disabledVariableIds = new Set(
      Object.entries(rawValues)
        .filter(([key, value]) => key.startsWith(ENABLED_PREFIX) && value === 'false')
        .map(([key]) => key.slice(ENABLED_PREFIX.length)),
    );

    const cleanedValues = Object.fromEntries(
      Object.entries(rawValues).filter(([key, value]) => {
        if (key.startsWith('__preset_')) return false;
        if (key.startsWith(ENABLED_PREFIX)) return value === 'false';
        if (disabledVariableIds.has(key)) return false;
        return typeof value === 'string';
      }),
    );

    const withTime = {
      ...cleanedValues,
      [PRESET_START_DATE_KEY]: currentTimeConfig?.startDate ?? null,
      [PRESET_END_DATE_KEY]: currentTimeConfig?.endDate ?? null,
      [PRESET_RELATIVE_DATE_KEY]: currentTimeConfig?.relativeDate ?? null,
    };
    return JSON.stringify(withTime);
  };

  const formik = useFormik({
    initialValues: { name: '' },
    validate: (values) => {
      const errors: Record<string, string> = {};
      if (!values.name.trim()) errors.name = t_i18n('Name is required');
      return errors;
    },
    onSubmit: (values, { resetForm }) => {
      commitAdd({
        variables: {
          id: workspace.id,
          input: {
            name: values.name,
            variable_values: buildPresetPayload(),
          },
        },
        onCompleted: () => {
          resetForm();
          onClose();
        },
      });
    },
  });

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>{t_i18n('Save preset')}</DialogTitle>
      <DialogContent>
        <form onSubmit={formik.handleSubmit}>
          <TextField
            fullWidth
            size="small"
            label={t_i18n('Preset name')}
            placeholder={t_i18n('My preset')}
            name="name"
            value={formik.values.name}
            onChange={formik.handleChange}
            error={!!formik.errors.name && formik.touched.name}
            helperText={formik.touched.name && formik.errors.name}
          />
          <DialogActions sx={{ px: 0, pt: 2 }}>
            <Button onClick={onClose}>{t_i18n('Cancel')}</Button>
            <Button
              type="submit"
              variant="contained"
              disabled={formik.isSubmitting || !formik.values.name.trim()}
            >
              {t_i18n('Save')}
            </Button>
          </DialogActions>
        </form>
      </DialogContent>
    </Dialog>
  );
};

export default PresetManagementDialog;
