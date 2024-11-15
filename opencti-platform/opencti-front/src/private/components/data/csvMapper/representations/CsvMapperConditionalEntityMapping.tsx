import React, { FunctionComponent } from 'react';
import MuiTextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import { Field, FieldProps } from 'formik';
import { CsvMapperColumnBasedFormData, CsvMapperRepresentationFormData } from '@components/data/csvMapper/representations/Representation';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { alphabet } from '@components/data/csvMapper/representations/attributes/AttributeUtils';
import { useCsvMapperContext } from '@components/data/csvMapper/representations/CsvMapperContext';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import SwitchField from '../../../../../components/fields/SwitchField';

interface CsvMapperConditionalEntityMappingProps
  extends FieldProps<CsvMapperColumnBasedFormData> {
  representation: CsvMapperRepresentationFormData;
  representationName: string;
}
const CsvMapperConditionalEntityMapping: FunctionComponent<
CsvMapperConditionalEntityMappingProps
> = ({ form, representationName, representation }) => {
  const { t_i18n } = useFormatter();
  const columnOptions = alphabet(26);
  const operatorOptions = [
    { label: t_i18n('Equal'), value: 'eq' },
    { label: t_i18n('Not equal'), value: 'not_eq' }];
  const { setFieldValue } = form;
  const columnBased = representation.column_based;
  const { columnIndex, setColumnIndex } = useCsvMapperContext();

  const handleColumnSelect = async (column: string | null) => {
    await setFieldValue(`${representationName}.column_based.column_reference`, column);
    if (!columnIndex && column) {
      setColumnIndex(column);
    } else {
      setColumnIndex('');
    }
  };

  const handleOperatorSelect = async (operator: { label: string, value: string } | null) => {
    await setFieldValue(`${representationName}.column_based.operator`, operator?.value);
  };
  return (
    <div style={{
      width: '100%',
      display: 'grid',
      gridTemplateColumns: '1.3fr 1fr 1fr 1fr',
      alignItems: 'center',
      margin: '30px 0px',
      gap: '10px',
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
        value={columnBased?.enabled
          ? columnBased?.column_reference || columnIndex
          : null
          }
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
                  borderColor: (!columnIndex && !columnBased?.column_reference)
                    ? 'rgb(244, 67, 54)'
                    : '',
                },
              },
            }}
          />
        )}
      />
      <MUIAutocomplete<{ label: string, value: string }>
        selectOnFocus
        openOnFocus
        autoSelect={false}
        autoHighlight
        options={operatorOptions}
        disabled={!columnBased?.enabled}
        value={
          columnBased?.enabled
            ? (operatorOptions.find((opt) => (opt.value === columnBased?.operator)) ?? operatorOptions.find((opt) => opt.value === 'eq'))
            : null
          }
        onChange={(_, val) => handleOperatorSelect(val)}
        sx={{ width: '100%' }}
        renderInput={(params) => (
          <MuiTextField
            {...params}
            label={t_i18n('Operator')}
            variant="outlined"
            size="small"
          />
        )}
      />
      <div style={{ marginBottom: '10px', marginRight: '10px' }}>
        <Field
          component={TextField}
          label={t_i18n('Value')}
          name={`${representationName}.column_based.value`}
          variant='standard'
          style={{ width: '100%' }}
          disabled={!representation.column_based?.enabled}
          error={!columnBased?.value && columnBased?.enabled}
          value={columnBased?.enabled ? columnBased.value : ''}
        />
      </div>
    </div>
  );
};

export default CsvMapperConditionalEntityMapping;
