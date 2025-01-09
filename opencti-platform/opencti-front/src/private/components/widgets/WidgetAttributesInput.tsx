import React, { FunctionComponent } from 'react';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import FormControl from '@mui/material/FormControl';
import type { WidgetColumn } from '../../../utils/widget/widget';
import { useFormatter } from '../../../components/i18n';

interface WidgetCreationAttributesProps {
  value: readonly WidgetColumn[],
  i: number,
  onChange: (i: number,
    key: string,
    value: (string | null)[],
  ) => void,
}

const WidgetAttributesInput: FunctionComponent<WidgetCreationAttributesProps> = ({
  value,
  i,
  onChange,
}) => {
  const { t_i18n } = useFormatter();
  const availableColumns: WidgetColumn[] = [
    { attribute: 'entity_type', label: 'Entity type' },
    { attribute: 'relationship_type', label: 'Relationship type' },
    { attribute: 'created_at', label: 'Creation date' },
    { attribute: 'createdBy.name', label: 'Author' },
    { attribute: 'objectMarking.definition', label: 'Marking' },
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
        value={value.map((c) => c.attribute)}
        onChange={(event) => onChange(
          i,
          'columns',
          event.target.value,
        )
        }
      >
        {availableColumns.map((v) => (
          <MenuItem
            key={v.attribute}
            value={v.attribute}
          >
            {t_i18n(v.label)}
          </MenuItem>
        ))}
      </Select>
    </FormControl>
  );
};

export default WidgetAttributesInput;
