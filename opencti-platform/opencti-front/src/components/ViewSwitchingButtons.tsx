import React, { FunctionComponent } from 'react';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { LibraryBooksOutlined, ViewModuleOutlined } from '@mui/icons-material';
import { FormatListGroup, Group, RelationManyToMany, VectorPolygon } from 'mdi-material-ui';
import { ToggleButtonGroup } from '@mui/material';
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
    <ToggleButtonGroup
      size="small"
      color="primary"
      exclusive={true}
      value={currentView}
    >
      {typeof handleChangeView === 'function' && !disableCards && (
        <Tooltip title={t_i18n('Cards view')}>
          <ToggleButton value="cards" aria-label="cards">
            <ViewModuleOutlined fontSize="small" color="primary" />
          </ToggleButton>
        </Tooltip>
      )}
      {typeof handleChangeView === 'function'
        && enableEntitiesView && (
        <Tooltip title={t_i18n('Entities view')}>
          <ToggleButton value="entities" aria-label="entities">
            <LibraryBooksOutlined
              fontSize="small"
            />
          </ToggleButton>
        </Tooltip>
      )}
      {enableEntitiesView && (
        <Tooltip title={t_i18n('Relationships view')}>
          <ToggleButton
            value="relationships"
            aria-label="relationships"
          >
            <RelationManyToMany
              fontSize="small"
            />
          </ToggleButton>
        </Tooltip>
      )}
      {typeof handleChangeView === 'function' && !enableEntitiesView && (
        <Tooltip title={t_i18n('Lines view')}>
          <ToggleButton
            value="lines"
            onClick={() => handleChangeView('lines')}
            aria-label="lines"
          >
            <FiligranIcon icon={ListViewIcon} size="small" />
          </ToggleButton>
        </Tooltip>
      )}
      {typeof handleChangeView === 'function' && enableSubEntityLines && (
        <Tooltip title={t_i18n('Sub entity lines view')}>
          <ToggleButton
            value="subEntityLines"
            aria-label="subEntityLines"
          >
            <FiligranIcon icon={SublistViewIcon} size="small" />
          </ToggleButton>
        </Tooltip>
      )}
      {typeof handleChangeView === 'function' && enableGraph && (
        <Tooltip title={t_i18n('Graph view')}>
          <ToggleButton value="graph" aria-label="graph">
            <VectorPolygon fontSize="small" color="primary" />
          </ToggleButton>
        </Tooltip>
      )}
      {typeof handleChangeView === 'function'
        && enableNestedView && (
        <Tooltip title={t_i18n('Nested view')}>
          <ToggleButton value="nested" aria-label="nested">
            <FormatListGroup fontSize="small" color="primary" />
          </ToggleButton>
        </Tooltip>
      )}
      {typeof handleChangeView === 'function'
        && enableContextualView && (
        <Tooltip
          title={t_i18n('Knowledge from related containers view')}
        >
          <ToggleButton value="contextual" aria-label="contextual">
            <Group
              fontSize="small"
              color={
                currentView === 'contextual' || !currentView
                  ? 'secondary'
                  : 'primary'
              }
            />
          </ToggleButton>
        </Tooltip>
      )}
    </ToggleButtonGroup>
  );
};

export default ViewSwitchingButtons;
