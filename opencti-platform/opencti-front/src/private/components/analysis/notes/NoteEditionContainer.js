import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import inject18n from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import NoteEditionOverview from './NoteEditionOverview';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
});

class NoteEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { currentTab: 0 };
  }

  handleChangeTab(event, value) {
    this.setState({ currentTab: value });
  }

  render() {
    const { t, classes, handleClose, note } = this.props;
    const { editContext } = note;
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update a note')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <NoteEditionOverview note={this.props.note} context={editContext} />
        </div>
      </div>
    );
  }
}

NoteEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  note: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const NoteEditionFragment = createFragmentContainer(NoteEditionContainer, {
  note: graphql`
    fragment NoteEditionContainer_note on Note {
      id
      ...NoteEditionOverview_note
      editContext {
        name
        focusOn
      }
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(NoteEditionFragment);
