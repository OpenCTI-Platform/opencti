import React, { FunctionComponent } from 'react';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { LibraryBooksOutlined, ViewModuleOutlined } from '@mui/icons-material';
import { FormatListGroup, Group, RelationManyToMany, VectorPolygon } from 'mdi-material-ui';
import { ToggleButtonGroup } from '@mui/material';
import { ListViewIcon, SublistViewIcon } from 'filigran-icon';
import FiligranIcon from '@components/common/FiligranIcon';
import { useFormatter } from './i18n';

interface ViewSwitchingButtonsProps {
  handleChangeView?: (value: string) => void;
  disableCards?: boolean,
  enableEntitiesView?: boolean,
  currentView?: string,
  enableSubEntityLines?: boolean,
  enableGraph?: boolean,
  enableNestedView?: boolean,
  enableContextualView?: boolean,
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
      color="secondary"
      exclusive={true}
      value={currentView}
      style={{ margin: '0 0 0 5px' }}
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
              color={
                currentView === 'entities'
                  ? 'secondary'
                  : 'primary'
                }
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
            color={
              currentView === 'relationships' || !currentView
                ? 'secondary'
                : 'primary'
              }
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
          <FiligranIcon icon={ListViewIcon} color="primary" size="small" />
        </ToggleButton>
      </Tooltip>
      )}
      {typeof handleChangeView === 'function' && enableSubEntityLines && (
      <Tooltip title={t_i18n('Sub entity lines view')}>
        <ToggleButton
          value="subEntityLines"
          aria-label="subEntityLines"
          style={{ height: 36 }}
        >
          <FiligranIcon icon={SublistViewIcon} color="secondary" size="small" />
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
