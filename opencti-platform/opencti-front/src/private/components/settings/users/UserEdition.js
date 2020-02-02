import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import AppBar from '@material-ui/core/AppBar';
import Tabs from '@material-ui/core/Tabs';
import Tab from '@material-ui/core/Tab';
import { Close } from '@material-ui/icons';
import { requestSubscription } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import UserEditionOverview from './UserEditionOverview';
import UserEditionPassword from './UserEditionPassword';
import UserEditionGroups from './UserEditionGroups';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
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
    backgroundColor: theme.palette.navAlt.background,
    color: theme.palette.header.text,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
});

const subscription = graphql`
  subscription UserEditionSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on User {
        ...UserEdition_user
      }
    }
  }
`;

class UserEdition extends Component {
  constructor(props) {
    super(props);
    this.state = { currentTab: 0 };
  }

  componentDidMount() {
    const sub = requestSubscription({
      subscription,
      variables: { id: this.props.user.id },
    });
    this.setState({ sub });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
  }

  handleChangeTab(event, value) {
    this.setState({ currentTab: value });
  }

  render() {
    const {
      t, classes, handleClose, user,
    } = this.props;
    const { editContext } = user;
    const external = user.external === true;
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}>
            <Close fontSize="small" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update a user')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <AppBar position="static" elevation={0} className={classes.appBar}>
            <Tabs
              value={this.state.currentTab}
              onChange={this.handleChangeTab.bind(this)}>
              <Tab label={t('Overview')} />
              <Tab disabled={external} label={t('Password')} />
              <Tab label={t('Groups')} />
            </Tabs>
          </AppBar>
          {this.state.currentTab === 0 && (
            <UserEditionOverview user={this.props.user} context={editContext}/>
          )}
          {this.state.currentTab === 1 && (
            <UserEditionPassword user={this.props.user} context={editContext}/>
          )}
          {this.state.currentTab === 2 && (
            <UserEditionGroups user={this.props.user} context={editContext}/>
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
