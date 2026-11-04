import React from 'react';
import * as PropTypes from 'prop-types';
import Drawer from '@mui/material/Drawer';
import Slide from '@mui/material/Slide';
import DataTableToolBar from './DataTableToolBar';
import { UserContext } from '../../../utils/hooks/useAuth';
import { OPEN_BAR_WIDTH, SMALL_BAR_WIDTH } from '@components/nav/navBarConstants';
import useDraftContext, { DRAFT_TOOLBAR_HEIGHT } from '../../../utils/hooks/useDraftContext';
import { useTheme } from '@mui/material/styles';

const bottomNavSx = {
  padding: 0,
  zIndex: 1,
  display: 'flex',
  height: 50,
  overflow: 'hidden',
};

const bottomNavWithLargePaddingSx = {
  zIndex: 1100,
  padding: '0 250px 0 0',
  display: 'flex',
  height: 50,
  overflow: 'hidden',
};

const bottomNavWithMediumPaddingSx = {
  zIndex: 1100,
  padding: '0 200px 0 0',
  display: 'flex',
  height: 50,
  overflow: 'hidden',
};

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

export const maxNumberOfObservablesToCopy = 1000;

const ToolBar = (props) => {
  const {
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    selectAll,
    filters,
    container,
    variant,
    deleteDisable,
    mergeDisable,
    trashOperationsEnabled,
    warning,
    warningMessage,
    type,
    noAuthor,
    noWarning,
    noMarking,
    handleCopy,
    search,
    taskScope,
    knowledgeEntityId,
  } = props;
  const theme = useTheme();
  const draftContext = useDraftContext();
  const navOpen = localStorage.getItem('navOpen') === 'true';
  const isOpen = numberOfSelectedElements > 0;
  const posBottom = draftContext ? DRAFT_TOOLBAR_HEIGHT : 0;

  let paperSx;
  switch (variant) {
    case 'large':
      paperSx = bottomNavWithLargePaddingSx;
      break;
    case 'medium':
      paperSx = bottomNavWithMediumPaddingSx;
      break;
    default:
      paperSx = bottomNavSx;
  }

  return (
    <UserContext.Consumer>
      {({ bannerSettings }) => (
        <Drawer
          anchor="bottom"
          variant="persistent"
          open={isOpen}
          slotProps={{
            paper: {
              variant: 'elevation',
              elevation: 1,
              sx: paperSx,
              style: {
                marginLeft: navOpen ? OPEN_BAR_WIDTH : SMALL_BAR_WIDTH,
                bottom: (bannerSettings?.bannerHeightNumber ?? 0) + posBottom,
                zIndex: theme.zIndex.appBar - 2,
              },
            },
          }}
        >
          <DataTableToolBar
            search={search}
            numberOfSelectedElements={numberOfSelectedElements}
            handleClearSelectedElements={handleClearSelectedElements}
            selectedElements={selectedElements}
            deSelectedElements={deSelectedElements}
            selectAll={selectAll}
            filters={filters}
            container={container}
            variant={variant}
            deleteDisable={deleteDisable}
            warning={warning}
            warningMessage={warningMessage}
            type={type}
            noAuthor={noAuthor}
            noWarning={noWarning}
            noMarking={noMarking}
            mergeDisable={mergeDisable}
            trashOperationsEnabled={trashOperationsEnabled}
            handleCopy={handleCopy}
            taskScope={taskScope}
            knowledgeEntityId={knowledgeEntityId}
          />
        </Drawer>
      )}
    </UserContext.Consumer>
  );
};

ToolBar.propTypes = {
  numberOfSelectedElements: PropTypes.number,
  handleClearSelectedElements: PropTypes.func,
  selectedElements: PropTypes.object,
  selectAll: PropTypes.bool,
  filters: PropTypes.object,
  container: PropTypes.object,
  variant: PropTypes.string,
  deleteDisable: PropTypes.bool,
  type: PropTypes.string,
  warning: PropTypes.bool,
  warningMessage: PropTypes.string,
  deSelectedElements: PropTypes.object,
  search: PropTypes.string,
  handleCopy: PropTypes.func,
  noAuthor: PropTypes.bool,
  noMarking: PropTypes.bool,
  noWarning: PropTypes.bool,
  mergeDisable: PropTypes.bool,
  trashOperationsEnabled: PropTypes.bool,
  taskScope: PropTypes.string,
  knowledgeEntityId: PropTypes.string,
};

export default ToolBar;
