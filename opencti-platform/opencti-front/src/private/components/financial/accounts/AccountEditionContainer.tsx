import { makeStyles } from '@mui/styles';
import { PreloadedQuery, usePreloadedQuery, graphql } from 'react-relay';
import { FunctionComponent } from 'react';
import { IconButton, Typography } from '@mui/material';
import { Close } from 'mdi-material-ui';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { AccountEditionContainerQuery } from './__generated__/AccountEditionContainerQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import AccountEditionOverview from './AccountEditionOverview';

const useStyles = makeStyles<Theme>((theme) => ({
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

interface AccountEditionContainerProps {
  handleClose: () => void
  queryRef: PreloadedQuery<AccountEditionContainerQuery>
}

export const accountEditionQuery = graphql`
  query AccountEditionContainerQuery($id: ID!) {
    financialAccount(id: $id) {
      ...AccountEditionOverview_financialAccount
      editContext {
        name
        focusOn
      }
    }
  }
`;

const AccountEditionContainer: FunctionComponent<AccountEditionContainerProps> = ({ handleClose, queryRef }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const queryData = usePreloadedQuery(accountEditionQuery, queryRef);

  if (queryData.financialAccount) {
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
            {t('Update an account')}
          </Typography>
          <SubscriptionAvatars context={queryData.financialAccount?.editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <AccountEditionOverview
            accountRef={queryData.financialAccount}
          />
        </div>
      </div>
    );
  }

  return <Loader variant={LoaderVariant.inElement} />;
};

export default AccountEditionContainer;
