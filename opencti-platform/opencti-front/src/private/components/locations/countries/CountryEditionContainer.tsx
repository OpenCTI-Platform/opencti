import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import CountryEditionOverview from './CountryEditionOverview';
import { Theme } from '../../../../components/Theme';
import { CountryEditionContainerQuery } from './__generated__/CountryEditionContainerQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

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
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
}));

interface CountryEditionContainerProps {
  handleClose: () => void;
  queryRef: PreloadedQuery<CountryEditionContainerQuery>;
}

export const countryEditionQuery = graphql`
  query CountryEditionContainerQuery($id: String!) {
    country(id: $id) {
      ...CountryEditionOverview_country
      editContext {
        name
        focusOn
      }
    }
  }
`;

const CountryEditionContainer: FunctionComponent<
CountryEditionContainerProps
> = ({ handleClose, queryRef }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const queryData = usePreloadedQuery(countryEditionQuery, queryRef);
  if (queryData.country) {
    return (
      <>
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
            {t('Update an country')}
          </Typography>
          <SubscriptionAvatars context={queryData.country.editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <CountryEditionOverview
            countryRef={queryData.country}
            enableReferences={useIsEnforceReference('Country')}
            context={queryData.country.editContext}
            handleClose={handleClose}
          />
        </div>
      </>
    );
  }
  return <Loader variant={LoaderVariant.inElement} />;
};

export default CountryEditionContainer;
