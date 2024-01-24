import MuiTextField from '@mui/material/TextField';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import React from 'react';
import Alert from '@mui/material/Alert';
import { FieldProps } from 'formik';

interface CsvMapperRepresentationAttributeOptionProps extends FieldProps<string> {
  placeholder: string
  info?: string
  tooltip?: string
}

const CsvMapperRepresentationAttributeOption = ({
  field,
  form,
  placeholder,
  tooltip,
  info,
}: CsvMapperRepresentationAttributeOptionProps) => {
  const { name, value } = field;
  const { setFieldValue } = form;

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: '8px', marginTop: '10px' }}>
        <MuiTextField
          style={{ flex: 1 }}
          type="text"
          value={value ?? ''}
          onChange={(event) => setFieldValue(name, event.target.value)}
          placeholder={placeholder}
        />
        {tooltip && (
        <Tooltip title={tooltip}>
          <InformationOutline
            fontSize="small"
            color="primary"
            style={{ cursor: 'default' }}
          />
        </Tooltip>
        )}
      </div>
      {info && <Alert style={{ marginTop: 8 }} severity="info">{info}</Alert>}
    </>
  );
};

export default CsvMapperRepresentationAttributeOption;
