import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import AppBar from '@mui/material/AppBar';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { Close } from '@mui/icons-material';
import inject18n from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import GroupEditionOverview from './GroupEditionOverview';
import GroupEditionPermissions from './GroupEditionPermissions';
import GroupEditionUsers from './GroupEditionUsers';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    color: theme.palette.navAlt.backgroundHeaderText,
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
    backgroundColor: theme.palette.navAlt.background,
    color: theme.palette.text.primary,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
});

const GroupEdition = ({
  t, classes, handleClose, group,
}) => {
  const [currentTab, setTab] = useState(0);
  const { editContext } = group;
  return (
    <div>
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          size="large">
          <Close fontSize="small" />
        </IconButton>
        <Typography variant="h6" classes={{ root: classes.title }}>
          {t('Update a group')}
        </Typography>
        <SubscriptionAvatars context={editContext} />
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <AppBar position="static" elevation={0} className={classes.appBar}>
          <Tabs value={currentTab} onChange={(event, value) => setTab(value)}>
            <Tab label={t('Overview')} />
            <Tab label={t('Permissions')} />
            <Tab label={t('Members')} />
          </Tabs>
        </AppBar>
        {currentTab === 0 && (
          <GroupEditionOverview group={group} context={editContext} />
        )}
        {currentTab === 1 && <GroupEditionPermissions group={group} />}
        {currentTab === 2 && <GroupEditionUsers group={group} />}
      </div>
    </div>
  );
};

GroupEdition.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  group: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const GroupEditionFragment = createFragmentContainer(GroupEdition, {
  group: graphql`
    fragment GroupEdition_group on Group {
      id
      ...GroupEditionOverview_group
      ...GroupEditionPermissions_group
      ...GroupEditionUsers_group
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
)(GroupEditionFragment);
