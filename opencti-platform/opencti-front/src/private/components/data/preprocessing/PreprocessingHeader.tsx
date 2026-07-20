import React, { FunctionComponent, useState } from 'react';
import { useTheme } from '@mui/styles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Switch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
import type { Theme } from '../../../../components/Theme';
import { getRule, toggleRule } from './preprocessingStore';

interface PreprocessingHeaderProps { ruleId: string; }

const PreprocessingHeader: FunctionComponent<PreprocessingHeaderProps> = ({ ruleId }) => {
  const theme = useTheme<Theme>();
  const [rule, setRule] = useState(getRule(ruleId));
  const handleToggle = () => { toggleRule(ruleId); setRule(getRule(ruleId)); };
  if (!rule) return null;
  return (
    <Paper variant="outlined" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: theme.spacing(1, 2), marginBottom: theme.spacing(1) }}>
      <Typography variant="h6">{rule.name}</Typography>
      {rule.description && <Typography variant="body2" color="textSecondary" style={{ flex: 1, marginLeft: 16 }}>{rule.description}</Typography>}
      <FormControlLabel
        control={<Switch checked={rule.active} onChange={handleToggle} color="secondary" />}
        label={rule.active ? 'Active' : 'Inactive'}
      />
    </Paper>
  );
};
export default PreprocessingHeader;
