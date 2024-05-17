import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Slide from '@mui/material/Slide';
import DataTableToolBar from './DataTableToolBar';
import { UserContext } from '../../../utils/hooks/useAuth';

const styles = () => ({
  bottomNav: {
    padding: 0,
    zIndex: 1,
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
  bottomNavWithLargePadding: {
    zIndex: 1100,
    padding: '0 250px 0 0',
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
  bottomNavWithMediumPadding: {
    zIndex: 1100,
    padding: '0 200px 0 0',
    display: 'flex',
    height: 50,
    overflow: 'hidden',
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

export const maxNumberOfObservablesToCopy = 1000;

class ToolBar extends Component {
  constructor(props) {
    super(props);
    this.state = {
      navOpen: localStorage.getItem('navOpen') === 'true',
      promoteToContainer: true,
    };
  }

  render() {
    const {
      classes,
      numberOfSelectedElements,
      handleClearSelectedElements,
      selectedElements,
      selectAll,
      filters,
      container,
      variant,
      deleteDisable,
      mergeDisable,
      deleteOperationEnabled,
      warning,
      warningMessage,
      type,
      noAuthor,
      noWarning,
      noMarking,
    } = this.props;
    const { navOpen } = this.state;
    const isOpen = numberOfSelectedElements > 0;
    let paperClass;
    switch (variant) {
      case 'large':
        paperClass = classes.bottomNavWithLargePadding;
        break;
      case 'medium':
        paperClass = classes.bottomNavWithMediumPadding;
        break;
      default:
        paperClass = classes.bottomNav;
    }
    return (
      <UserContext.Consumer>
        {({ bannerSettings }) => (
          <Drawer
            anchor="bottom"
            variant="persistent"
            classes={{ paper: paperClass }}
            open={isOpen}
            PaperProps={{
              variant: 'elevation',
              elevation: 1,
              style: {
                marginLeft: navOpen ? 180 : 55,
                bottom: bannerSettings.bannerHeightNumber,
              },
            }}
          >
            <DataTableToolBar
              numberOfSelectedElements={numberOfSelectedElements}
              handleClearSelectedElements={handleClearSelectedElements}
              selectedElements={selectedElements}
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
              deleteOperationEnabled={deleteOperationEnabled}
            />
          </Drawer>
        )}
      </UserContext.Consumer>
    );
  }
}

ToolBar.propTypes = {
  classes: PropTypes.object,
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
  deleteOperationEnabled: PropTypes.bool,
};

export default R.compose(withStyles(styles))(ToolBar);
