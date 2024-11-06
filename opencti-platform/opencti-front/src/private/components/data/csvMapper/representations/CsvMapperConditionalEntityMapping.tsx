import React, { FunctionComponent } from 'react';
import MuiTextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import { Field, FieldProps } from 'formik';
import { CsvMapperColumnBasedFormData, CsvMapperRepresentationFormData } from '@components/data/csvMapper/representations/Representation';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { alphabet } from '@components/data/csvMapper/representations/attributes/AttributeUtils';
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
    { label: t_i18n('Equal'), value: ('eq') },
    { label: t_i18n('Not equal'), value: 'not_eq' }];

  const { setFieldValue } = form;

  const handleToggleSelect = async (isDynamic: boolean) => {
    console.log('DYNAMIC', isDynamic);
    await setFieldValue(`${representationName}.column_based.enabled`, !!isDynamic);
  };

  const handleColumnSelect = async (column: string | null) => {
    await setFieldValue(`${representationName}.column_based.column_reference`, column);
  };

  const handleOperatorSelect = async (operator: { label: string, value: string } | null) => {
    await setFieldValue(`${representationName}.column_based.operator`, operator?.value);
  };

  return (
    <div style={{ display: 'flex', alignItems: 'center' }}>
      <Field
        component={SwitchField}
        type="checkbox"
        name={`${representationName}.column_based.enabled`}
        label={t_i18n('Entity dynamic mapping')}
        onChange={(e: any) => handleToggleSelect(e.target.checked)}
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
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
      }}
      >
        <MUIAutocomplete
          selectOnFocus
          openOnFocus
          autoSelect={false}
          autoHighlight
          options={columnOptions}
          disabled={!representation.column_based?.enabled}
          value={representation.column_based?.column_reference}
          onChange={(_, val) => handleColumnSelect(val)}
          sx={{ width: '180px', marginLeft: '95px' }}
          renderInput={(params) => (
            <MuiTextField
              {...params}
              label={t_i18n('Column index')}
              variant="outlined"
              size="small"
            />
          )}
        />
        <MUIAutocomplete<{ label: string, value: string }>
          selectOnFocus
          openOnFocus
          autoSelect={false}
          autoHighlight
          options={operatorOptions}
          disabled={!representation.column_based?.enabled}
          value={operatorOptions.find((opt) => (opt.value === representation.column_based?.operator)) ?? undefined}
          onChange={(_, val) => handleOperatorSelect(val)}
          sx={{ width: '150px', marginLeft: '5px' }}
          renderInput={(params) => (
            <MuiTextField
              {...params}
              label={t_i18n('Operator')}
              variant="outlined"
              size="small"
            />
          )}
        />
        <div style={{ width: '145px', marginLeft: '5px', marginBottom: '10px' }}>
          <Field
            component={TextField}
            label={t_i18n('Value')}
            name={`${representationName}.column_based.value`}
            variant="standard"
            disabled={!representation.column_based?.enabled}
          />
        </div>
      </div>
    </div>
  );
};

export default CsvMapperConditionalEntityMapping;
