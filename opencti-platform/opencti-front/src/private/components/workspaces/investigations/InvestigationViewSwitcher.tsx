import React, { FunctionComponent } from 'react';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import Tooltip from '@mui/material/Tooltip';
import { ViewColumnOutlined } from '@mui/icons-material';
import { VectorPolygon } from 'mdi-material-ui';
import { useFormatter } from '../../../../components/i18n';

export type InvestigationView = 'graph' | 'matrix' | 'matrix-b';

interface InvestigationViewSwitcherProps {
  view: InvestigationView;
  onChange: (view: InvestigationView) => void;
}

// Distinct colours for the two A/B matrix variants so they are easy to tell
// apart during user testing.
const MATRIX_A_COLOR = '#00b0ff'; // blue
const MATRIX_B_COLOR = '#ffa000'; // amber

const InvestigationViewSwitcher: FunctionComponent<InvestigationViewSwitcherProps> = ({
  view,
  onChange,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <ToggleButtonGroup
      size="small"
      exclusive
      value={view}
      onChange={(_, value) => {
        if (value) onChange(value as InvestigationView);
      }}
    >
      <ToggleButton value="graph" aria-label={t_i18n('Graph view')}>
        <Tooltip title={t_i18n('Graph view')}>
          <VectorPolygon fontSize="small" color={view === 'graph' ? 'secondary' : 'primary'} />
        </Tooltip>
      </ToggleButton>
      <ToggleButton value="matrix" aria-label={t_i18n('Matrix view A')}>
        <Tooltip title={t_i18n('Matrix view A')}>
          <ViewColumnOutlined
            fontSize="small"
            sx={{ color: view === 'matrix' ? MATRIX_A_COLOR : undefined }}
            color={view === 'matrix' ? undefined : 'primary'}
          />
        </Tooltip>
      </ToggleButton>
      <ToggleButton value="matrix-b" aria-label={t_i18n('Matrix view B')}>
        <Tooltip title={t_i18n('Matrix view B')}>
          <ViewColumnOutlined
            fontSize="small"
            sx={{ color: view === 'matrix-b' ? MATRIX_B_COLOR : undefined }}
            color={view === 'matrix-b' ? undefined : 'primary'}
          />
        </Tooltip>
      </ToggleButton>
    </ToggleButtonGroup>
  );
};

export default InvestigationViewSwitcher;
