import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import MenuItem from '@mui/material/MenuItem';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import type { SxProps, Theme } from '@mui/material/styles';
import { useFormatter } from '../i18n';

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

// FDS-WORKAROUND #43 (second site): kept on MUI Select. `DashboardTimeFilters`
// passes `selectSx` to draw a border on this field while a relative date is
// active — a product state signal on the field shell, exactly the gap recorded
// for CustomViewPreviewEntitySelector. The library owns the field's border and
// exposes no state tint, so converting would drop the signal. Remove when the
// library ships a token-based way to tint the shell — see
// fds-migration/LIBRARY-FEEDBACK.md #43 (V2 backlog)
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
        <MenuItem value="days-1">{t_i18n('Last 24 hours')}</MenuItem>
        <MenuItem value="days-7">{t_i18n('Last 7 days')}</MenuItem>
        <MenuItem value="months-1">{t_i18n('Last month')}</MenuItem>
        <MenuItem value="months-3">{t_i18n('Last 3 months')}</MenuItem>
        <MenuItem value="months-6">{t_i18n('Last 6 months')}</MenuItem>
        <MenuItem value="years-1">{t_i18n('Last year')}</MenuItem>
      </Select>
    </FormControl>
  );
};

export default DashboardRelativeDateSelect;
