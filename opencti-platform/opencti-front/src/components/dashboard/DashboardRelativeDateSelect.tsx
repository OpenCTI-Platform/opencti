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
