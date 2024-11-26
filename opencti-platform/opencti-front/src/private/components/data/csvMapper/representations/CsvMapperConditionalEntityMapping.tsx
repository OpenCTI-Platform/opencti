import React, { FunctionComponent } from 'react';
import MuiTextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import { Field, FieldProps } from 'formik';
import { CsvMapperColumnBasedFormData, CsvMapperRepresentationFormData } from '@components/data/csvMapper/representations/Representation';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { alphabet } from '@components/data/csvMapper/representations/attributes/AttributeUtils';
import { useCsvMapperContext } from '@components/data/csvMapper/CsvMapperContext';
import { useTheme } from '@mui/styles';
import { Option } from '@components/common/form/ReferenceField';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import SwitchField from '../../../../../components/fields/SwitchField';
import type { Theme } from '../../../../../components/Theme';

interface CsvMapperConditionalEntityMappingProps
  extends FieldProps<CsvMapperColumnBasedFormData> {
  representation: CsvMapperRepresentationFormData;
  representationName: string;
}

const CsvMapperConditionalEntityMapping: FunctionComponent<
CsvMapperConditionalEntityMappingProps
> = ({ form, representationName, representation }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { dynamicMappingColumn, setDynamicMappingColumn } = useCsvMapperContext();

  const columnOptions = alphabet(26);
  const operatorOptions: Option[] = [
    { label: t_i18n('Equal'), value: 'eq' },
    { label: t_i18n('Not equal'), value: 'not_eq' }];
  const { setFieldValue } = form;

  const columnBased = representation.column_based;

  const handleColumnSelect = async (column: string | null) => {
    await setFieldValue(`${representationName}.column_based.column_reference`, column);
    if (column) {
      setDynamicMappingColumn(column);
    }
  };

  const handleOperatorSelect = async (operator: Option | null) => {
    await setFieldValue(`${representationName}.column_based.operator`, operator?.value);
  };

  const onToggleDynamicMapping = async (val: string) => {
    if (val === 'false') {
      await setFieldValue(`${representationName}.column_based.column_reference`, null);
      await setFieldValue(`${representationName}.column_based.operator`, null);
    } else {
      await setFieldValue(`${representationName}.column_based.column_reference`, dynamicMappingColumn ?? null);
      await setFieldValue(`${representationName}.column_based.operator`, 'eq');
    }
  };

  return (
    <div style={{
      width: '100%',
      display: 'grid',
      gridTemplateColumns: '1.3fr 1fr 1fr 1fr',
      alignItems: 'center',
      marginTop: `${theme.spacing(3)} 0 `,
      gap: theme.spacing(1),
    }}
    >
      <div style={{
        display: 'flex',
        alignItems: 'center',
      }}
      >
        <Field
          component={SwitchField}
          type="checkbox"
          name={`${representationName}.column_based.enabled`}
          onChange={(_: string, val: string) => onToggleDynamicMapping(val)}
          label={t_i18n('Entity dynamic mapping')}
        />
        <Tooltip
          title={t_i18n(
            'If this option is selected, we will dynamically map the column value that you provide to the entity.',
          )}
        >
          <InformationOutline
            fontSize="small"
            color="primary"
            style={{ cursor: 'default' }}
          />
        </Tooltip>
      </div>
      <MUIAutocomplete
        selectOnFocus
        openOnFocus
        autoSelect={false}
        autoHighlight
        options={columnOptions}
        disabled={!columnBased?.enabled}
        value={columnBased?.column_reference ?? null}
        onChange={(_, val) => handleColumnSelect(val)}
        sx={{ width: '100%' }}
        renderInput={(params) => (
          <MuiTextField
            {...params}
            label={t_i18n('Column index')}
            variant="outlined"
            size="small"
            InputProps={{
              ...params.InputProps,
              sx: {
                '& fieldset': {
                  borderColor: (!columnBased?.column_reference)
                    ? 'rgb(244, 67, 54)'
                    : '',
                },
              },
            }}
          />
        )}
      />
      <MUIAutocomplete<Option>
        selectOnFocus
        openOnFocus
        autoComplete
        autoSelect={false}
        autoHighlight
        options={operatorOptions}
        disabled={!columnBased?.enabled}
        value={operatorOptions.find((opt) => opt.value === columnBased?.operator) ?? null}
        onChange={(_, val) => handleOperatorSelect(val)}
        sx={{ width: '100%' }}
        renderInput={(params) => (
          <MuiTextField
            {...params}
            label={t_i18n('Operator')}
            variant="outlined"
            size="small"
            InputProps={{
              ...params.InputProps,
              sx: {
                '& fieldset': {
                  borderColor: (!columnBased?.operator)
                    ? 'rgb(244, 67, 54)'
                    : '',
                },
              },
            }}
          />
        )}
      />
      <div style={{ marginBottom: '10px', marginRight: '10px' }}>
        <Field
          component={TextField}
          label={t_i18n('Value')}
          name={`${representationName}.column_based.value`}
          value={columnBased?.enabled ? columnBased.value : ''}
          variant='standard'
          style={{ width: '100%' }}
          disabled={!representation.column_based?.enabled}
          error={!columnBased?.value && columnBased?.enabled}
        />
      </div>
    </div>
  );
};

export default CsvMapperConditionalEntityMapping;
