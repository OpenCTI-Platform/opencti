import React, { FunctionComponent, useState } from 'react';
import MuiTextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import { Field, FieldProps } from 'formik';
import { CsvMapperColumnBasedFormData, CsvMapperRepresentationFormData } from '@components/data/csvMapper/representations/Representation';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { alphabet } from '@components/data/csvMapper/representations/attributes/AttributeUtils';
import { RepresentationAttributeForm } from '@components/data/csvMapper/representations/attributes/CsvMapperRepresentationAttributeForm';
import { SelectChangeEvent } from '@mui/material/Select';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import SwitchField from '../../../../../components/fields/SwitchField';

interface CsvMapperConditionalEntityMappingProps
  extends FieldProps<RepresentationAttributeForm> {
  representation: CsvMapperRepresentationFormData;
  representationName: string;
}

const CsvMapperConditionalEntityMapping: FunctionComponent<
CsvMapperConditionalEntityMappingProps
> = ({ form, field }) => {
  const { t_i18n } = useFormatter();
  const options = alphabet(26);
  const operators = ['Equal', 'Not equal'];
  const [selectedOption, setSelectedOption] = useState();
  const [selectedOperator, setSelectedOperator] = useState();

  const { name, value } = field;
  const { setFieldValue } = form;

  const handleValueSelect = async () => {
    await setFieldValue('value', value);
  };
  const handleColumnSelect = async (
    column: any,
  ) => {
    if (!value) {
      setSelectedOption(column);

      const newValue: CsvMapperColumnBasedFormData = {
        column_reference: column ?? undefined,
        operator: 'eq',
        value: 'dd',
      };
      await setFieldValue(name, newValue);
    } else {
      setSelectedOption(column);
      const updatedValue: CsvMapperColumnBasedFormData = {
        ...value,
        column_reference: column ?? undefined,
        operator: 'eq',
        value: 'dd',
      };
      await setFieldValue(name, updatedValue);
    }
  };

  const handleParentSelect = () => {
    setFieldValue(
      'has_dynamic_mapping',
      value,
    );
    // if (csvMapper.has_entity_dynamic_mapping === false) {
    //   setDisabledColumn(true);
    // }
  };

  const handleOperatorSelect = (event: SelectChangeEvent) => {
    setSelectedOperator(event.target.value);
  };

  return (
    <div style={{ display: 'flex', alignItems: 'center' }}>
      <Field
        component={SwitchField}
        type="checkbox"
        name="has_entity_dynamic_mapping"
        label={t_i18n('Entity dynamic mapping')}
        onChange={handleParentSelect}
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
          options={options}
          value={selectedOption}
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
        <MUIAutocomplete
          selectOnFocus
          openOnFocus
          autoSelect={false}
          autoHighlight
          options={operators}
          value={selectedOperator}
          onChange={() => handleOperatorSelect}
          sx={{ width: '150px', marginLeft: '5px' }}
          renderInput={(params) => (
            <MuiTextField
              {...params}
              label={t_i18n('Operators')}
              variant="outlined"
              size="small"
            />
          )}
        />
        <div style={{ width: '145px', marginLeft: '5px', marginBottom: '10px' }}>
          <Field
            component={TextField}
            name="value"
            label={t_i18n('Value')}
            onChange={handleValueSelect}
          />
        </div>
      </div>
    </div>
  );
};

export default CsvMapperConditionalEntityMapping;
