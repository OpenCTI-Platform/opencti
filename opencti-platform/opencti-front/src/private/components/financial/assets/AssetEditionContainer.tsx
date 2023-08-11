import { makeStyles } from '@mui/styles';
import { PreloadedQuery, usePreloadedQuery, graphql } from 'react-relay';
import { FunctionComponent } from 'react';
import { IconButton, Typography } from '@mui/material';
import { Close } from 'mdi-material-ui';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { AssetEditionContainerQuery } from './__generated__/AssetEditionContainerQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import AssetEditionOverview from './AssetEditionOverview';

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

interface AssetEditionContainerProps {
  handleClose: () => void
  queryRef: PreloadedQuery<AssetEditionContainerQuery>
}

export const assetEditionQuery = graphql`
  query AssetEditionContainerQuery($id: ID!) {
    financialAsset(id: $id) {
      ...AssetEditionOverview_financialAsset
      editContext {
        name
        focusOn
      }
    }
  }
`;

const AssetEditionContainer: FunctionComponent<AssetEditionContainerProps> = ({ handleClose, queryRef }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const queryData = usePreloadedQuery(assetEditionQuery, queryRef);

  if (queryData.financialAsset) {
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
            {t('Update an asset')}
          </Typography>
          <SubscriptionAvatars context={queryData.financialAsset?.editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <AssetEditionOverview assetRef={queryData.financialAsset} />
        </div>
      </div>
    );
  }

  return <Loader variant={LoaderVariant.inElement} />;
};

export default AssetEditionContainer;
