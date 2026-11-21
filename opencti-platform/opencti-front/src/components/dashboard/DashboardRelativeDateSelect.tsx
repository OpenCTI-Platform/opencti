import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import MenuItem from '@mui/material/MenuItem';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import type { SxProps, Theme } from '@mui/material/styles';
import { useFormatter } from '../i18n';
import { RELATIVE_DATE_OPTIONS } from './dashboardTimeRange';

interface DashboardRelativeDateSelectProps {
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  formControlClassName?: string;
  selectClassName?: string;
  selectSx?: SxProps<Theme>;
  width?: number;
  labelId?: string;
}

// FDS-WORKAROUND #43 (second site): kept on MUI Select — the library exposes no
// per-state border tint. Remove when it does; see fds-migration/LIBRARY-FEEDBACK.md #43
// and fds-migration/MIGRATION-DECISIONS.md#field-state-tint
const DashboardRelativeDateSelect = ({
  value,
  onChange,
  disabled = false,
  formControlClassName,
  selectClassName,
  selectSx,
  labelId = 'relative',
}: DashboardRelativeDateSelectProps) => {
  const { t_i18n } = useFormatter();

  const handleChange = (event: SelectChangeEvent<string>) => {
    onChange(event.target.value);
  };

  return (
    <FormControl
      size="small"
      sx={{ width: 200 }}
      variant="outlined"
      className={formControlClassName}
    >
      <InputLabel id={labelId} variant="outlined">
        {t_i18n('Relative time')}
      </InputLabel>
      <Select
        labelId={labelId}
        value={value}
        onChange={handleChange}
        label={t_i18n('Relative time')}
        variant="outlined"
        className={selectClassName}
        disabled={disabled}
        sx={selectSx}
      >
        <MenuItem value="none">{t_i18n('None')}</MenuItem>
        {RELATIVE_DATE_OPTIONS.map(({ value: optionValue, label }) => (
          <MenuItem key={optionValue} value={optionValue}>{t_i18n(label)}</MenuItem>
        ))}
      </Select>
    </FormControl>
  );
};

export default DashboardRelativeDateSelect;
