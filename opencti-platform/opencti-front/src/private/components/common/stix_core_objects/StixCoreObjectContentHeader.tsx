import React, { FunctionComponent } from 'react';
import Tooltip from '@mui/material/Tooltip';
import ToggleButton from '@mui/material/ToggleButton';
import { Link } from 'react-router-dom';
import { DifferenceOutlined, DriveFileRenameOutlineOutlined, NewspaperOutlined } from '@mui/icons-material';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import { useFormatter } from '../../../../components/i18n';
import useDraftContext from '../../../../utils/hooks/useDraftContext';

interface StixCoreObjectContentHeaderProps {
  currentMode?: string;
  modes: string[];
  disableMapping: boolean;
  disableEditor: boolean;
}

const StixCoreObjectContentHeader: FunctionComponent<StixCoreObjectContentHeaderProps> = ({
  currentMode,
  modes,
  disableMapping,
  disableEditor,
}) => {
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();

  return (
    <div style={{
      margin: '-65px 0 0 0',
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
            <NewspaperOutlined
              fontSize="small"
              color={currentMode === 'content' ? 'primary' : 'inherit'}
            />
          </ToggleButton>
        </Tooltip>
        )}
        {modes.includes('editor') && (
        <Tooltip title={t_i18n('Editor view')}>
          <ToggleButton
            component={Link}
            to='editor'
            selected={currentMode === 'editor'}
            value={'editor'}
            disabled={disableEditor}
          >
            <DriveFileRenameOutlineOutlined
              fontSize="small"
              color={currentMode === 'editor' ? 'primary' : 'inherit'}
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
            disabled={disableMapping || !!draftContext}
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
