import React, { FunctionComponent } from 'react';
import Tooltip from '@mui/material/Tooltip';
import ToggleButton from '@mui/material/ToggleButton';
import { Link } from 'react-router-dom';
import { DifferenceOutlined } from '@mui/icons-material';
import HistoryEduIcon from '@mui/icons-material/HistoryEdu';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import PlaylistPlayIcon from '@mui/icons-material/PlaylistPlay';
import { useFormatter } from '../../../../components/i18n';

interface StixCoreObjectContentHeaderProps {
  currentMode?: string;
  modes: string[];
  disabled: boolean;
}

const StixCoreObjectContentHeader: FunctionComponent<StixCoreObjectContentHeaderProps> = ({
  currentMode,
  modes,
  disabled,
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
              color={currentMode === 'content' ? 'primary' : 'inherit'}
            />
          </ToggleButton>
        </Tooltip>
        )}
        {modes.includes('suggested_mapping') && (
        <Tooltip title={t_i18n('Suggested mapping view')}>
          <ToggleButton
            component={Link}
            to='suggested_mapping'
            selected={currentMode === 'suggested_mapping'}
            value={'suggested_mapping'}
            disabled={disabled}
          >
            <PlaylistPlayIcon
              fontSize="small"
              color={currentMode === 'suggested_mapping' ? 'primary' : 'inherit'}
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
            disabled={disabled}
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
