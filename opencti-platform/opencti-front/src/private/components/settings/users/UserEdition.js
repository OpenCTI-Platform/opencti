import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { Close } from '@mui/icons-material';
import inject18n from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import UserEditionOverview from './UserEditionOverview';
import UserEditionPassword from './UserEditionPassword';
import UserEditionGroups from './UserEditionGroups';

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
  title: {
    float: 'left',
  },
});

class UserEdition extends Component {
  constructor(props) {
    super(props);
    this.state = { currentTab: 0 };
  }

  handleChangeTab(event, value) {
    this.setState({ currentTab: value });
  }

  render() {
    const { t, classes, handleClose, user } = this.props;
    const { editContext } = user;
    const external = user.external === true;
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
            {t('Update a user')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs
              value={this.state.currentTab}
              onChange={this.handleChangeTab.bind(this)}
            >
              <Tab label={t('Overview')} />
              <Tab disabled={external} label={t('Password')} />
              <Tab label={t('Groups')} />
            </Tabs>
          </Box>
          {this.state.currentTab === 0 && (
            <UserEditionOverview user={this.props.user} context={editContext} />
          )}
          {this.state.currentTab === 1 && (
            <UserEditionPassword user={this.props.user} context={editContext} />
          )}
          {this.state.currentTab === 2 && (
            <UserEditionGroups user={this.props.user} context={editContext} />
          )}
        </div>
      </div>
    );
  }
}

UserEdition.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  user: PropTypes.object,
  me: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const UserEditionFragment = createFragmentContainer(UserEdition, {
  user: graphql`
    fragment UserEdition_user on User {
      id
      external
      ...UserEditionOverview_user
      ...UserEditionPassword_user
      ...UserEditionGroups_user
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
)(UserEditionFragment);
