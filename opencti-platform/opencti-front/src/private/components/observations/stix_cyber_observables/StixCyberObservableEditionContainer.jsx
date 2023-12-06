import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import StixCyberObservableEditionOverview from './StixCyberObservableEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import StixCyberObservableDelete from './StixCyberObservableDelete';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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

const StixCyberObservableEditionContainer = (props) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const { handleClose, stixCyberObservable, isArtifact = false } = props;
  const { editContext } = stixCyberObservable;

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
          {t_i18n('Update an observable')}
        </Typography>
        <SubscriptionAvatars context={editContext} />
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <StixCyberObservableEditionOverview
          stixCyberObservable={stixCyberObservable}
          enableReferences={useIsEnforceReference('Stix-Cyber-Observable')}
          context={editContext}
          handleClose={handleClose}
        />
        <StixCyberObservableDelete
          id={stixCyberObservable.id}
          isArtifact={isArtifact}
        />
      </div>
    </div>
  );
};

const StixCyberObservableEditionFragment = createFragmentContainer(
  StixCyberObservableEditionContainer,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservableEditionContainer_stixCyberObservable on StixCyberObservable {
        id
        ...StixCyberObservableEditionOverview_stixCyberObservable
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default StixCyberObservableEditionFragment;
