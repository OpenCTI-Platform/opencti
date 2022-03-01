import React, { useState } from 'react';
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
import GroupEditionOverview from './GroupEditionOverview';
import GroupEditionPermissions from './GroupEditionPermissions';
import GroupEditionUsers from './GroupEditionUsers';

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

const GroupEdition = ({ t, classes, handleClose, group }) => {
  const [currentTab, setTab] = useState(0);
  const { editContext } = group;
  return (
    <div>
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          size="large"
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6" classes={{ root: classes.title }}>
          {t('Update a group')}
        </Typography>
        <SubscriptionAvatars context={editContext} />
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={currentTab} onChange={(event, value) => setTab(value)}>
            <Tab label={t('Overview')} />
            <Tab label={t('Permissions')} />
            <Tab label={t('Members')} />
          </Tabs>
        </Box>
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
