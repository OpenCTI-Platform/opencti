import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import { makeStyles } from '@mui/styles';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import AttackPatternEditionOverview from './AttackPatternEditionOverview';
import AttackPatternEditionDetails from './AttackPatternEditionDetails';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { useFormatter } from '../../../../components/i18n';

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
}));

const AttackPatternEditionContainer = (props) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const { handleClose, attackPattern } = props;
  const { editContext } = attackPattern;

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
          {t('Update an attack pattern')}
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
          <AttackPatternEditionOverview
            attackPattern={attackPattern}
            enableReferences={useIsEnforceReference('Attack-Pattern')}
            context={editContext}
            handleClose={handleClose}
          />
        )}
        {currentTab === 1 && (
          <AttackPatternEditionDetails
            attackPattern={attackPattern}
            enableReferences={useIsEnforceReference('Attack-Pattern')}
            context={editContext}
            handleClose={handleClose}
          />
        )}
      </div>
    </div>
  );
};

const AttackPatternEditionFragment = createFragmentContainer(
  AttackPatternEditionContainer,
  {
    attackPattern: graphql`
      fragment AttackPatternEditionContainer_attackPattern on AttackPattern {
        id
        ...AttackPatternEditionOverview_attackPattern
        ...AttackPatternEditionDetails_attackPattern
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default AttackPatternEditionFragment;
