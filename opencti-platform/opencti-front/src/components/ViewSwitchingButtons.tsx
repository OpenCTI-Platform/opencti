import React, { FunctionComponent } from 'react';
import Tooltip from '@mui/material/Tooltip';
import { LibraryBooksOutlined, ViewModuleOutlined } from '@mui/icons-material';
import { FormatListGroup, Group, RelationManyToMany, VectorPolygon } from 'mdi-material-ui';
import { ButtonGroup, ButtonGroupItem } from '@filigran/design-system';
import FiligranIcon from '@components/common/FiligranIcon';
import { ListViewIcon, SublistViewIcon } from 'filigran-icon';
import { useFormatter } from './i18n';

interface ViewSwitchingButtonsProps {
  handleChangeView?: (value: string) => void;
  disableCards?: boolean;
  enableEntitiesView?: boolean;
  currentView?: string;
  enableSubEntityLines?: boolean;
  enableGraph?: boolean;
  enableNestedView?: boolean;
  enableContextualView?: boolean;
}

// The library item declares a 16x16 glyph.
const GLYPH = { fontSize: 16 };

const ViewSwitchingButtons: FunctionComponent<ViewSwitchingButtonsProps> = ({
  handleChangeView,
  disableCards,
  enableEntitiesView,
  currentView,
  enableSubEntityLines,
  enableGraph,
  enableNestedView,
  enableContextualView,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <ButtonGroup
      size="md"
      value={currentView}
      onValueChange={handleChangeView}
      aria-label={t_i18n('Change view')}
    >
      {typeof handleChangeView === 'function' && !disableCards && (
        <Tooltip title={t_i18n('Cards view')}>
          <ButtonGroupItem
            value="cards"
            aria-label="cards"
            icon={<ViewModuleOutlined sx={GLYPH} />}
          />
        </Tooltip>
      )}
      {typeof handleChangeView === 'function' && enableEntitiesView && (
        <Tooltip title={t_i18n('Entities view')}>
          <ButtonGroupItem
            value="entities"
            aria-label="entities"
            icon={<LibraryBooksOutlined sx={GLYPH} />}
          />
        </Tooltip>
      )}
      {enableEntitiesView && (
        <Tooltip title={t_i18n('Relationships view')}>
          <ButtonGroupItem
            value="relationships"
            aria-label="relationships"
            icon={<RelationManyToMany sx={GLYPH} />}
          />
        </Tooltip>
      )}
      {typeof handleChangeView === 'function' && !enableEntitiesView && (
        <Tooltip title={t_i18n('Lines view')}>
          <ButtonGroupItem
            value="lines"
            aria-label="lines"
            icon={<FiligranIcon icon={ListViewIcon} size={16} />}
          />
        </Tooltip>
      )}
      {typeof handleChangeView === 'function' && enableSubEntityLines && (
        <Tooltip title={t_i18n('Sub entity lines view')}>
          <ButtonGroupItem
            value="subEntityLines"
            aria-label="subEntityLines"
            icon={<FiligranIcon icon={SublistViewIcon} size={16} />}
          />
        </Tooltip>
      )}
      {typeof handleChangeView === 'function' && enableGraph && (
        <Tooltip title={t_i18n('Graph view')}>
          <ButtonGroupItem
            value="graph"
            aria-label="graph"
            icon={<VectorPolygon sx={GLYPH} />}
          />
        </Tooltip>
      )}
      {typeof handleChangeView === 'function' && enableNestedView && (
        <Tooltip title={t_i18n('Nested view')}>
          <ButtonGroupItem
            value="nested"
            aria-label="nested"
            icon={<FormatListGroup sx={GLYPH} />}
          />
        </Tooltip>
      )}
      {typeof handleChangeView === 'function' && enableContextualView && (
        <Tooltip title={t_i18n('Knowledge from related containers view')}>
          <ButtonGroupItem
            value="contextual"
            aria-label="contextual"
            icon={<Group sx={GLYPH} />}
          />
        </Tooltip>
      )}
    </ButtonGroup>
  );
};

export default ViewSwitchingButtons;
