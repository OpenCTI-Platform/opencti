/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles/index';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import IconButton from '@material-ui/core/IconButton';
import Slide from '@material-ui/core/Slide';
import { MoreVertOutlined } from '@material-ui/icons';
import inject18n from '../../../../../components/i18n';
import { toastGenericError } from '../../../../../utils/bakedToast';
import CyioAddNotes from '../../../analysis/notes/CyioAddNotes';
import CyioAddExternalReferences from '../../../analysis/external_references/CyioAddExternalReferences';
import CyioCoreObjectLabelsView from '../../../common/stix_core_objects/CyioCoreObjectLabelsView';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  menuItem: {
    width: '170px',
    margin: '0px 20px',
    justifyContent: 'center',
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction='up' ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class EntitiesNotesPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      isOpen: false,
      openExternalRef: false,
    };
  }

  render() {
    const {
      classes,
      t,
      history,
      node,
    } = this.props;
    return (
      <div className={classes.container}>
        <IconButton aria-haspopup='true'>
          <MoreVertOutlined />
        </IconButton>
      </div>
    );
  }
}

EntitiesNotesPopover.propTypes = {
  node: PropTypes.object,
  handleOpenMenu: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(EntitiesNotesPopover);
