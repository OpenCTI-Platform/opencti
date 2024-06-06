import React, { FunctionComponent } from 'react';
import Tooltip from '@mui/material/Tooltip';
import ToggleButton from '@mui/material/ToggleButton';
import { Link } from 'react-router-dom';
import { DifferenceOutlined } from '@mui/icons-material';
import HistoryEduIcon from '@mui/icons-material/HistoryEdu';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import { useFormatter } from '../../../../components/i18n';

interface StixCoreObjectContentHeaderProps {
  currentMode?: string;
  modes: string[];
}

const StixCoreObjectContentHeader: FunctionComponent<StixCoreObjectContentHeaderProps> = ({
  currentMode,
  modes,
}) => {
  const { t_i18n } = useFormatter();

  return (
    <div style={{
      margin: '-75px 0 0 0',
      float: 'right',
    }}
    >
      <ToggleButtonGroup size="small" exclusive={true}>
        {modes.includes('content') && (
        <Tooltip title={t_i18n('Content view')}>
          <ToggleButton
            component={Link}
            to=''
            selected={currentMode === 'content'}
            value={'content'}
          >
            <HistoryEduIcon
              fontSize="small"
              color={currentMode === 'mapping' ? 'inherit' : 'primary'}
            />
          </ToggleButton>
        </Tooltip>
        )}
        {modes.includes('mapping') && (
        <Tooltip title={t_i18n('Content mapping view')}>
          <ToggleButton
            component={Link}
            to='mapping'
            selected={currentMode === 'mapping'}
            value={'mapping'}
          >
            <DifferenceOutlined
              fontSize="small"
              color={currentMode === 'mapping' ? 'primary' : 'inherit'}
            />
          </ToggleButton>
        </Tooltip>
        )}
      </ToggleButtonGroup>
    </div>
  );
};

export default StixCoreObjectContentHeader;
