import React, { FunctionComponent } from 'react';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import FormControl from '@mui/material/FormControl';
import type { WidgetColumn } from '../../../utils/widget/widget';
import { useFormatter } from '../../../components/i18n';

interface WidgetCreationAttributesProps {
  columns: readonly WidgetColumn[],
  i: number,
  handleChangeDataValidationColumns: (i: number,
    key: string,
    value: (string | null)[],
  ) => void,
}

const WidgetCreationAttributes: FunctionComponent<WidgetCreationAttributesProps> = ({
  columns,
  i,
  handleChangeDataValidationColumns,
}) => {
  const { t_i18n } = useFormatter();
  const availableColumns: WidgetColumn[] = [
    { attribute: 'entity_type' },
    { attribute: 'relationship_type' },
    { attribute: 'created_at' },
    { attribute: 'createdBy.name' },
    { attribute: 'objectMarking' },
  ];
  return (
    <FormControl
      fullWidth={true}
      style={{
        flex: 1,
        marginRight: 20,
        width: '100%',
      }}
    >
      <InputLabel>{t_i18n('Attribute')}</InputLabel>
      <Select
        fullWidth={true}
        multiple={true}
        value={columns.map((c) => c.attribute)}
        onChange={(event) => handleChangeDataValidationColumns(
          i,
          'columns',
          event.target.value,
        )
        }
      >
        {availableColumns.map((value) => (
          <MenuItem
            key={value.attribute}
            value={value.attribute}
          >
            {value.attribute}
          </MenuItem>
        ))}
      </Select>
    </FormControl>
  );
};

export default WidgetCreationAttributes;
