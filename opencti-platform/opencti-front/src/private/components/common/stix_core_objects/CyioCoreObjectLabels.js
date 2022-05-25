import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, map, take, sortWith, prop, ascend, pipe,
} from 'ramda';
import { withTheme, withStyles } from '@material-ui/core/styles';
import Chip from '@material-ui/core/Chip';
import Slide from '@material-ui/core/Slide';
import {
  List, ListItem, Button, IconButton,
} from '@material-ui/core';
import Popover from '@material-ui/core/Popover';
import MoreHorizIcon from '@material-ui/icons/MoreHoriz';
import inject18n from '../../../../components/i18n';
import { hexToRGB } from '../../../../utils/Colors';
import { truncate } from '../../../../utils/String';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = () => ({
  objectLabel: {
    display: 'flex',
  },
  labels: {
    margin: 0,
    padding: 0,
  },
  label: {
    height: 25,
    fontSize: 12,
    margin: '0 7px 7px 0',
  },
  labelInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    marginRight: 7,
  },
  labelInSearch: {
    height: 25,
    fontSize: 12,
    margin: '0 7px 0 0',
  },
  labelInput: {
    margin: '4px 0 0 10px',
    float: 'right',
  },
});

class CyioCoreObjectLabels extends Component {
  constructor(props) {
    super(props);
    this.state = {
      popoverAnchorEl: null,
      openedPopover: null,
      windowWidth: window.innerWidth,
      labelCount: 2,
    };
  }

  componentDidMount() {
    this.handleWindowChange();
  }

  componentDidUpdate(prevProps) {
    if (this.state.windowWidth !== window.innerWidth) {
      this.handleWindowChange();
    }
  }

  handleWindowChange() {
    this.setState({ windowWidth: window.innerWidth });
    if (window.innerWidth < 1670) {
      this.setState({ labelCount: 1 });
    } else {
      this.setState({ labelCount: 2 });
    }
  }

  handlePopoverOpen(event) {
    this.setState({ popoverAnchorEl: event.currentTarget, openedPopover: true });
  }

  handlePopoverClose() {
    this.setState({ popoverAnchorEl: null, openedPopover: false });
  }

  render() {
    const {
      classes, labels, t, onClick, variant, theme,
    } = this.props;
    const {
      labelCount,
    } = this.state;
    let style = classes.label;
    if (variant === 'inList') {
      style = classes.labelInList;
    }
    if (variant === 'inSearch') {
      style = classes.labelInSearch;
    }
    // const labelsNodes = pipe(
    //   map((n) => n.node),
    //   sortWith([ascend(prop('value'))]),
    // )(labels.edges);
    const labelsNodes = pipe(
      map((n) => n),
      sortWith([ascend(prop('name'))]),
    )(labels);
    return (
      <div className={classes.objectLabel}>
        <div>
          {labelsNodes.length > 0 ? (
            map(
              (label) => (
                <Chip
                  key={label.id}
                  variant="outlined"
                  classes={{ root: style }}
                  label={truncate(label.name, 10)}
                  style={{
                    color: label.color,
                    borderColor: label.color,
                    backgroundColor: hexToRGB(label.color),
                  }}
                  onClick={
                    typeof onClick === 'function'
                      ? onClick.bind(this, 'label_name', label.name, label.name)
                      : null
                  }
                />
              ),
              take(labelCount, labelsNodes),
            )
          ) : (
            <Chip
              classes={{ root: style }}
              variant="outlined"
              label={t('No label')}
              style={{
                color: theme.palette.type === 'dark' ? '#ffffff' : '#000000',
                borderColor:
                  theme.palette.type === 'dark' ? '#ffffff' : '#000000',
                backgroundColor: hexToRGB(
                  theme.palette.type === 'dark' ? '#ffffff' : 'transparent',
                ),
              }}
              onClick={
                typeof onClick === 'function'
                  ? onClick.bind(this, 'label_name', null, null)
                  : null
              }
            />
          )}
        </div>
        {labelsNodes.length > labelCount && (
          <MoreHorizIcon
            onMouseEnter={(e) => this.handlePopoverOpen(e)}
            onMouseLeave={this.handlePopoverClose.bind(this)}
          />
        )}
        <Popover
          id="mouse-over-popover"
          className={classes.popover}
          classes={{ paper: classes.paper }}
          style={{ pointerEvents: 'none' }}
          open={this.state.openedPopover}
          anchorEl={this.state.popoverAnchorEl}

          anchorOrigin={{
            vertical: 'bottom',
            horizontal: 'center',
          }}
          transformOrigin={{
            vertical: 'top',
            horizontal: 'center',
          }}
          onClose={this.handlePopoverClose.bind(this)}
        >
          <List>
            {labelsNodes.slice(labelCount).map((label, i) => (
              <ListItem key={i}>
                <Chip
                  key={label.id}
                  variant="outlined"
                  classes={{ root: style }}
                  label={label.name}
                  style={{
                    color: label.color,
                    borderColor: label.color,
                    backgroundColor: hexToRGB(label.color),
                  }}
                  onClick={
                    typeof onClick === 'function'
                      ? onClick.bind(this, 'label_name', label.name, label.name)
                      : null
                  }
                />
              </ListItem>
            ))}
          </List>
        </Popover>
      </div>
    );
  }
}

CyioCoreObjectLabels.propTypes = {
  classes: PropTypes.object.isRequired,
  theme: PropTypes.object,
  t: PropTypes.func,
  variant: PropTypes.string,
  onClick: PropTypes.func,
  labels: PropTypes.object,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(CyioCoreObjectLabels);
