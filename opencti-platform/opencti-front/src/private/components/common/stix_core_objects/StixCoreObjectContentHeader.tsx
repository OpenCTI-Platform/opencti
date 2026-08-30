import React, { FunctionComponent } from 'react';
import Tooltip from '@mui/material/Tooltip';
import { Link } from 'react-router-dom';
import { DifferenceOutlined, DriveFileRenameOutlineOutlined, NewspaperOutlined } from '@mui/icons-material';
import { ButtonGroup, ButtonGroupItem } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import useDraftContext from '../../../../utils/hooks/useDraftContext';

interface StixCoreObjectContentHeaderProps {
  currentMode?: string;
  modes: string[];
  disableMapping: boolean;
  disableEditor: boolean;
}

// The library item declares a 16x16 glyph; the MUI buttons drew theirs at
// fontSize="small" (20px).
const GLYPH = { fontSize: 16 };

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
      margin: '-70px 0 0 0',
      float: 'right',
    }}
    >
      {/* Each segment NAVIGATES, so it stays a real <a href> through `asChild`
          (lib #193, for LIBRARY-FEEDBACK #56). The group takes no
          onValueChange: the route IS the state, which is why `value` is the
          current mode and nothing writes it back. */}
      <ButtonGroup
        size="sm"
        value={currentMode}
        aria-label={t_i18n('Change view')}
      >
        {modes.includes('content') && (
          <Tooltip title={t_i18n('Content view')}>
            <ButtonGroupItem
              asChild
              value="content"
              aria-label={t_i18n('Content view')}
              icon={<NewspaperOutlined sx={GLYPH} />}
            >
              <Link to="" />
            </ButtonGroupItem>
          </Tooltip>
        )}
        {modes.includes('editor') && (
          <Tooltip title={t_i18n('Editor view')}>
            <ButtonGroupItem
              asChild
              value="editor"
              aria-label={t_i18n('Editor view')}
              icon={<DriveFileRenameOutlineOutlined sx={GLYPH} />}
              disabled={disableEditor}
            >
              <Link to="editor" />
            </ButtonGroupItem>
          </Tooltip>
        )}
        {modes.includes('mapping') && (
          <Tooltip title={t_i18n('Content mapping view')}>
            <ButtonGroupItem
              asChild
              value="mapping"
              aria-label={t_i18n('Content mapping view')}
              icon={<DifferenceOutlined sx={GLYPH} />}
              disabled={disableMapping || !!draftContext}
            >
              <Link to="mapping" />
            </ButtonGroupItem>
          </Tooltip>
        )}
      </ButtonGroup>
    </div>
  );
};

export default StixCoreObjectContentHeader;
