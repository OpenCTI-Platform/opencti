import React, { FunctionComponent } from 'react';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import Tooltip from '@mui/material/Tooltip';
import { ViewColumnOutlined } from '@mui/icons-material';
import { VectorPolygon } from 'mdi-material-ui';
import { useFormatter } from '../../../../components/i18n';

export type InvestigationView = 'graph' | 'matrix';

interface InvestigationViewSwitcherProps {
  view: InvestigationView;
  onChange: (view: InvestigationView) => void;
}

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
      style={{ marginLeft: 10 }}
    >
      <ToggleButton value="graph" aria-label={t_i18n('Graph view')}>
        <Tooltip title={t_i18n('Graph view')}>
          <VectorPolygon fontSize="small" color={view === 'graph' ? 'secondary' : 'primary'} />
        </Tooltip>
      </ToggleButton>
      <ToggleButton value="matrix" aria-label={t_i18n('Matrix view')}>
        <Tooltip title={t_i18n('Matrix view')}>
          <ViewColumnOutlined fontSize="small" color={view === 'matrix' ? 'secondary' : 'primary'} />
        </Tooltip>
      </ToggleButton>
    </ToggleButtonGroup>
  );
};

export default InvestigationViewSwitcher;
