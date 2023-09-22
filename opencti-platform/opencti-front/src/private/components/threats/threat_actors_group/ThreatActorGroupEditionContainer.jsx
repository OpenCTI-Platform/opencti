import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import ThreatActorGroupEditionOverview from './ThreatActorGroupEditionOverview';
import ThreatActorGroupEditionDetails from './ThreatActorGroupEditionDetails';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

const useStyles = makeStyles((theme) => ({
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
  container: {
    padding: '10px 20px 20px 20px',
  },
  title: {
    float: 'left',
  },
}));

const ThreatActorGroupEditionContainer = ({ handleClose, threatActorGroup }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const { editContext } = threatActorGroup;
  const [currentTab, setCurrentTab] = useState(0);
  const handleChangeTab = (event, value) => setCurrentTab(value);
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
          {t('Update a threat actor group')}
        </Typography>
        <SubscriptionAvatars context={editContext} />
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={currentTab} onChange={handleChangeTab}>
            <Tab label={t('Overview')} />
            <Tab label={t('Details')} />
          </Tabs>
        </Box>
        {currentTab === 0 && (
          <ThreatActorGroupEditionOverview
            threatActorGroup={threatActorGroup}
            enableReferences={useIsEnforceReference('Threat-Actor-Group')}
            context={editContext}
            handleClose={handleClose}
          />
        )}
        {currentTab === 1 && (
          <ThreatActorGroupEditionDetails
            threatActorGroup={threatActorGroup}
            enableReferences={useIsEnforceReference('Threat-Actor-Group')}
            context={editContext}
            handleClose={handleClose}
          />
        )}
      </div>
    </div>
  );
};

const ThreatActorGroupEditionFragment = createFragmentContainer(
  ThreatActorGroupEditionContainer,
  {
    threatActorGroup: graphql`
      fragment ThreatActorGroupEditionContainer_ThreatActorGroup on ThreatActorGroup {
        id
        ...ThreatActorGroupEditionOverview_ThreatActorGroup
        ...ThreatActorGroupEditionDetails_ThreatActorGroup
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default ThreatActorGroupEditionFragment;
