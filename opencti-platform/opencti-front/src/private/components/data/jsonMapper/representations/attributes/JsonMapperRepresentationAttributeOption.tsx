import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import React from 'react';
import Alert from '@mui/material/Alert';
import { FieldProps } from 'formik';
import { Input } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../../../components/Theme';

interface JsonMapperRepresentationAttributeOptionProps extends FieldProps<string> {
  placeholder: string;
  info?: string;
  tooltip?: string;
}

const JsonMapperRepresentationAttributeOption = ({
  field,
  form,
  placeholder,
  tooltip,
  info,
}: JsonMapperRepresentationAttributeOptionProps) => {
  const theme = useTheme<Theme>();
  const { name, value } = field;
  const { setFieldValue } = form;

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), marginTop: theme.spacing(1.25) }}>
        <Input
          className="flex-1"
          type="text"
          value={value ?? ''}
          onChange={(event) => setFieldValue(name, event.target.value)}
          placeholder={placeholder}
          aria-label={placeholder}
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

export default JsonMapperRepresentationAttributeOption;
