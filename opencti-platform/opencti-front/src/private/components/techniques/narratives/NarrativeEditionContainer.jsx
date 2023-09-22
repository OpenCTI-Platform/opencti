import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import NarrativeEditionOverview from './NarrativeEditionOverview';
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

const NarrativeEditionContainer = (props) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const { handleClose, narrative } = props;
  const { editContext } = narrative;

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
          {t('Update a narrative')}
        </Typography>
        <SubscriptionAvatars context={editContext} />
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <NarrativeEditionOverview
          narrative={narrative}
          enableReferences={useIsEnforceReference('Narrative')}
          context={editContext}
          handleClose={handleClose}
        />
      </div>
    </div>
  );
};

const NarrativeEditionFragment = createFragmentContainer(
  NarrativeEditionContainer,
  {
    narrative: graphql`
      fragment NarrativeEditionContainer_narrative on Narrative {
        id
        ...NarrativeEditionOverview_narrative
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default NarrativeEditionFragment;
