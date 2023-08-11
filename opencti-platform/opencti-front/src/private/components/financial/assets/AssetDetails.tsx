import { Chip, Grid, Paper, Typography } from '@mui/material';
import { FunctionComponent } from 'react';
import { makeStyles } from '@mui/styles';
import { Asset_financialAsset$data } from './__generated__/Asset_financialAsset.graphql';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import { displayCurrencyCode } from '../accounts/AccountCreation';
import { valToKey } from '../../../../utils/Localization';
import { FinancialAssetType } from './AssetCreation';

const useStyles = makeStyles<Theme>(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  chip: {
    fontSize: 12,
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: '0',
    width: '100%',
    backgroundColor: 'rgba(229,152,137, 0.08)',
    color: '#e59889',
  },
}));

interface AssetDetailsComponentProps {
  asset: Asset_financialAsset$data
}

const AssetDetailsComponent: FunctionComponent<AssetDetailsComponentProps> = ({ asset }: { asset: Asset_financialAsset$data }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={4}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Asset Type')}
            </Typography>
            <Chip
              classes={{ root: classes.chip }}
              label={t(valToKey(asset.asset_type, FinancialAssetType))}
            />
          </Grid>
          <Grid item={true} xs={4}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Asset Value')}
            </Typography>
            <Chip
              classes={{ root: classes.chip }}
              label={asset.asset_value}
            />
          </Grid>
          <Grid item={true} xs={4}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Currency Code')}
            </Typography>
            <Chip
              classes={{ root: classes.chip }}
              label={displayCurrencyCode(asset.currency_code || t('Unknown'))}
            />
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default AssetDetailsComponent;
