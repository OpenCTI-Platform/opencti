import React, { FunctionComponent } from 'react';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { LibraryBooksOutlined, ViewListOutlined, ViewModuleOutlined } from '@mui/icons-material';
import { FormatListGroup, Group, RelationManyToMany, VectorPolygon } from 'mdi-material-ui';
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
    <>
      {typeof handleChangeView === 'function' && !disableCards && (
        <ToggleButton value="cards" aria-label="cards">
          <Tooltip title={t_i18n('Cards view')}>
            <ViewModuleOutlined fontSize="small" color="primary" />
          </Tooltip>
        </ToggleButton>
      )}
      {typeof handleChangeView === 'function'
        && enableEntitiesView && (
        <ToggleButton value="entities" aria-label="entities">
          <Tooltip title={t_i18n('Entities view')}>
            <LibraryBooksOutlined
              fontSize="small"
              color={
                currentView === 'entities'
                  ? 'secondary'
                  : 'primary'
                }
            />
          </Tooltip>
        </ToggleButton>
      )}
      {enableEntitiesView && (
        <ToggleButton
          value="relationships"
          aria-label="relationships"
        >
          <Tooltip title={t_i18n('Relationships view')}>
            <RelationManyToMany
              fontSize="small"
              color={
                currentView === 'relationships' || !currentView
                  ? 'secondary'
                  : 'primary'
                }
            />
          </Tooltip>
        </ToggleButton>
      )}
      {typeof handleChangeView === 'function'
        && !enableEntitiesView && (
        <ToggleButton value="lines" onClick={() => handleChangeView('lines')} aria-label="lines">
          <Tooltip title={t_i18n('Lines view')}>
            <ViewListOutlined
              fontSize="small"
              color={
                currentView === 'lines' || !currentView
                  ? 'secondary'
                  : 'primary'
                }
            />
          </Tooltip>
        </ToggleButton>
      )}
      {typeof handleChangeView === 'function' && enableSubEntityLines && (
        <ToggleButton value="subEntityLines" aria-label="subEntityLines">
          <Tooltip title={t_i18n('Sub entity lines view')}>
            <ViewListOutlined
              fontSize="small"
              color={
                currentView === 'subEntityLines'
                  ? 'secondary'
                  : 'primary'
                }
            />
          </Tooltip>
        </ToggleButton>
      )}
      {typeof handleChangeView === 'function' && enableGraph && (
        <ToggleButton value="graph" aria-label="graph">
          <Tooltip title={t_i18n('Graph view')}>
            <VectorPolygon fontSize="small" color="primary" />
          </Tooltip>
        </ToggleButton>
      )}
      {typeof handleChangeView === 'function'
        && enableNestedView && (
        <ToggleButton value="nested" aria-label="nested">
          <Tooltip title={t_i18n('Nested view')}>
            <FormatListGroup fontSize="small" color="primary" />
          </Tooltip>
        </ToggleButton>
      )}
      {typeof handleChangeView === 'function'
        && enableContextualView && (
        <ToggleButton value="contextual" aria-label="contextual">
          <Tooltip
            title={t_i18n('Knowledge from related containers view')}
          >
            <Group
              fontSize="small"
              color={
                currentView === 'contextual' || !currentView
                  ? 'secondary'
                  : 'primary'
                }
            />
          </Tooltip>
        </ToggleButton>
      )}
    </>
  );
};

export default ViewSwitchingButtons;
