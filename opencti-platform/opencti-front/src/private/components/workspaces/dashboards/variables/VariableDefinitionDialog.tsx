import React, { useState } from 'react';
import { graphql } from 'react-relay';
import MUIAutocomplete from '@mui/material/Autocomplete';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import MenuItem from '@mui/material/MenuItem';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import MUITextField from '@mui/material/TextField';
import { useFormik } from 'formik';
import EntitySelectWithTypes from '../../../../../components/fields/EntitySelectWithTypes';
import { useFormatter } from '../../../../../components/i18n';
import { fetchQuery } from '../../../../../relay/environment';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import useVocabularyCategory from '../../../../../utils/hooks/useVocabularyCategory';
import { killChainPhasesSearchQuery } from '../../../settings/KillChainPhases';
import { vocabularySearchQuery } from '../../../settings/VocabularyQuery';
import { getNodes } from '../../../../../utils/connection';
import { KillChainPhasesSearchQuery$data } from '../../../settings/__generated__/KillChainPhasesSearchQuery.graphql';

const variableAddMutation = graphql`
  mutation VariableDefinitionDialogAddMutation($id: ID!, $input: DashboardVariableInput!) {
    workspaceVariableAdd(id: $id, input: $input) {
      id
      manifest
      variables {
        id
        name
        filterKey
        filterKeyType
        defaultValue
      }
    }
  }
`;

type FilterKeyType = 'entity_ref' | 'vocabulary' | 'kill_chain' | 'boolean' | 'numeric' | 'text';

const FILTER_KEY_TYPES: Array<{ value: FilterKeyType; label: string }> = [
  { value: 'entity_ref', label: 'Entity selector' },
  { value: 'vocabulary', label: 'Vocabulary' },
  { value: 'kill_chain', label: 'Kill chain phase' },
  { value: 'boolean', label: 'Boolean' },
  { value: 'numeric', label: 'Numeric' },
  { value: 'text', label: 'Text' },
];

interface KillChainOption {
  label: string;
  value: string;
  kill_chain_name: string;
  phase_name: string;
}

interface VocabOption {
  label: string;
  value: string;
}

interface VariableDefinitionDialogProps {
  open: boolean;
  workspaceId: string;
  onClose: () => void;
}

const VariableDefinitionDialog: React.FC<VariableDefinitionDialogProps> = ({
  open,
  workspaceId,
  onClose,
}) => {
  const { t_i18n } = useFormatter();
  const [commitAdd] = useApiMutation(variableAddMutation);
  const { categoriesOptions } = useVocabularyCategory();

  // Entity ref state
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [entityValue, setEntityValue] = useState<any>(null);

  // Vocabulary state
  const [vocabCategory, setVocabCategory] = useState<string>('');
  const [vocabOptions, setVocabOptions] = useState<VocabOption[]>([]);
  const [vocabValue, setVocabValue] = useState<VocabOption | null>(null);

  // Kill chain state
  const [killChainOptions, setKillChainOptions] = useState<KillChainOption[]>([]);
  const [killChainValue, setKillChainValue] = useState<KillChainOption | null>(null);

  const resetExtraState = () => {
    setEntityValue(null);
    setVocabCategory('');
    setVocabOptions([]);
    setVocabValue(null);
    setKillChainOptions([]);
    setKillChainValue(null);
  };

  const handleVocabCategoryChange = (category: string) => {
    setVocabCategory(category);
    setVocabValue(null);
    if (!category) return;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    fetchQuery(vocabularySearchQuery, { category }).toPromise().then((data: any) => {
      const opts: VocabOption[] = (data?.vocabularies?.edges ?? []).map((e: any) => ({
        label: e.node.name,
        value: e.node.name,
      }));
      setVocabOptions(opts);
    });
  };

  const searchKillChains = (search = '') => {
    fetchQuery(killChainPhasesSearchQuery, { search })
      .toPromise()
      .then((data) => {
        const dataNodes = getNodes((data as KillChainPhasesSearchQuery$data).killChainPhases);
        dataNodes.sort((a, b) => (a.x_opencti_order ?? 0) - (b.x_opencti_order ?? 0));
        const phases: KillChainOption[] = dataNodes.map((node) => ({
          label: `[${node.kill_chain_name}] ${node.phase_name}`,
          value: node.id,
          kill_chain_name: node.kill_chain_name,
          phase_name: node.phase_name,
        }));
        setKillChainOptions(phases);
      })
      .catch(() => {
        setKillChainOptions([]);
      });
  };

  const asStringOrNull = (value: unknown): string | null => {
    if (value === null || value === undefined || value === '') {
      return null;
    }
    return String(value);
  };

  const getDefaultValue = (filterKeyType: FilterKeyType, simpleDefault: string): string | null => {
    switch (filterKeyType) {
      case 'entity_ref': return asStringOrNull(entityValue?.value);
      case 'vocabulary': return asStringOrNull(vocabValue?.value);
      case 'kill_chain': return killChainValue ? JSON.stringify({ kill_chain_name: killChainValue.kill_chain_name, phase_name: killChainValue.phase_name }) : null;
      default: return asStringOrNull(simpleDefault);
    }
  };

  const formik = useFormik({
    initialValues: {
      name: '',
      filterKeyType: 'entity_ref' as FilterKeyType,
      defaultValue: '',
    },
    validate: (values) => {
      const errors: Record<string, string> = {};
      if (!values.name.trim()) errors.name = t_i18n('Name is required');
      return errors;
    },
    onSubmit: (values, { resetForm }) => {
      commitAdd({
        variables: {
          id: workspaceId,
          input: {
            name: values.name,
            filterKey: values.filterKeyType === 'vocabulary'
              ? (vocabCategory || 'vocabulary')
              : values.filterKeyType,
            filterKeyType: values.filterKeyType,
            defaultValue: getDefaultValue(values.filterKeyType, values.defaultValue),
          },
        },
        onCompleted: () => {
          resetForm();
          resetExtraState();
          onClose();
        },
      });
    },
  });

  const handleClose = () => {
    formik.resetForm();
    resetExtraState();
    onClose();
  };

  const handleTypeChange = (e: SelectChangeEvent<string>) => {
    formik.setFieldValue('filterKeyType', e.target.value as FilterKeyType);
    formik.setFieldValue('defaultValue', '');
    resetExtraState();
  };

  const fkt = formik.values.filterKeyType;

  return (
    <Dialog open={open} onClose={handleClose} fullWidth maxWidth="sm">
      <form onSubmit={formik.handleSubmit}>
        <DialogTitle>{t_i18n('Add dashboard variable')}</DialogTitle>
        <DialogContent>

          {/* Name */}
          <MUITextField
            fullWidth
            margin="normal"
            label={t_i18n('Variable name')}
            name="name"
            value={formik.values.name}
            onChange={formik.handleChange}
            error={!!formik.errors.name && formik.touched.name}
            helperText={formik.touched.name && formik.errors.name}
          />

          {/* Type */}
          <FormControl fullWidth margin="normal">
            <InputLabel>{t_i18n('Type')}</InputLabel>
            <Select
              value={formik.values.filterKeyType}
              onChange={handleTypeChange}
              label={t_i18n('Type')}
            >
              {FILTER_KEY_TYPES.map((type) => (
                <MenuItem key={type.value} value={type.value}>
                  {t_i18n(type.label)}
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {/* ── Entity selector ── */}
          {fkt === 'entity_ref' && (
            <Box sx={{ mt: 2 }}>
              <EntitySelectWithTypes
                label={t_i18n('Default entity (optional)')}
                value={entityValue}
                handleChange={(val: any) => setEntityValue(val)}
                entitiesToExclude={[]}
              />
            </Box>
          )}

          {/* ── Vocabulary ── */}
          {fkt === 'vocabulary' && (
            <>
              <MUIAutocomplete
                sx={{ mt: 2 }}
                options={categoriesOptions}
                getOptionLabel={(o) => (typeof o === 'string' ? o : o.label)}
                value={categoriesOptions.find((o) => o.value === vocabCategory) ?? null}
                onChange={(_, val) => handleVocabCategoryChange((val as any)?.value ?? '')}
                renderInput={(params) => (
                  <MUITextField {...params} label={t_i18n('Vocabulary category')} fullWidth />
                )}
              />
              {vocabCategory && (
                <MUIAutocomplete
                  sx={{ mt: 2 }}
                  options={vocabOptions}
                  getOptionLabel={(o) => o.label}
                  value={vocabValue}
                  onChange={(_, val) => setVocabValue(val as VocabOption | null)}
                  renderInput={(params) => (
                    <MUITextField {...params} label={t_i18n('Vocabulary value (optional)')} fullWidth />
                  )}
                />
              )}
            </>
          )}

          {/* ── Kill chain phase ── */}
          {fkt === 'kill_chain' && (
            <MUIAutocomplete
              sx={{ mt: 2 }}
              options={killChainOptions}
              getOptionLabel={(o) => o.label}
              value={killChainValue}
              filterOptions={(x) => x}
              onOpen={() => searchKillChains('')}
              onFocus={() => searchKillChains('')}
              onInputChange={(_, val, reason) => {
                if (reason === 'input' || reason === 'clear') {
                  searchKillChains(val);
                }
              }}
              onChange={(_, val) => setKillChainValue(val as KillChainOption | null)}
              renderInput={(params) => (
                <MUITextField {...params} label={t_i18n('Kill chain phase (optional)')} fullWidth />
              )}
            />
          )}

          {/* ── Boolean ── */}
          {fkt === 'boolean' && (
            <FormControl fullWidth margin="normal">
              <InputLabel>{t_i18n('Value (optional)')}</InputLabel>
              <Select
                name="defaultValue"
                value={formik.values.defaultValue}
                onChange={formik.handleChange}
                label={t_i18n('Value (optional)')}
              >
                <MenuItem value="">{t_i18n('No default')}</MenuItem>
                <MenuItem value="true">true</MenuItem>
                <MenuItem value="false">false</MenuItem>
              </Select>
            </FormControl>
          )}

          {/* ── Numeric ── */}
          {fkt === 'numeric' && (
            <MUITextField
              fullWidth
              margin="normal"
              label={t_i18n('Value (optional)')}
              name="defaultValue"
              type="number"
              value={formik.values.defaultValue}
              onChange={formik.handleChange}
            />
          )}

          {/* ── Text ── */}
          {fkt === 'text' && (
            <MUITextField
              fullWidth
              margin="normal"
              label={t_i18n('Value (optional)')}
              name="defaultValue"
              value={formik.values.defaultValue}
              onChange={formik.handleChange}
            />
          )}

        </DialogContent>
        <DialogActions>
          <Button onClick={handleClose}>{t_i18n('Cancel')}</Button>
          <Button type="submit" variant="contained" disabled={formik.isSubmitting}>
            {t_i18n('Add')}
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
};

export default VariableDefinitionDialog;
