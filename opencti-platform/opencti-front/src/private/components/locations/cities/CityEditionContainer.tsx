import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import CityEditionOverview from './CityEditionOverview';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { CityEditionContainerQuery } from './__generated__/CityEditionContainerQuery.graphql';
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
  container: {
    padding: '10px 20px 20px 20px',
  },
  title: {
    float: 'left',
  },
}));

interface CityEditionContainerProps {
  queryRef: PreloadedQuery<CityEditionContainerQuery>;
  handleClose: () => void;
}

export const cityEditionQuery = graphql`
  query CityEditionContainerQuery($id: String!) {
    city(id: $id) {
      ...CityEditionOverview_city
      editContext {
        name
        focusOn
      }
    }
  }
`;
const CityEditionContainer: FunctionComponent<CityEditionContainerProps> = ({
  queryRef,
  handleClose,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const queryData = usePreloadedQuery(cityEditionQuery, queryRef);
  if (queryData.city === null) {
    return <ErrorNotFound />;
  }
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
          {t('Update a city')}
        </Typography>
        <SubscriptionAvatars context={queryData.city.editContext} />
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <CityEditionOverview
          cityRef={queryData.city}
          enableReferences={useIsEnforceReference('City')}
          context={queryData.city.editContext}
          handleClose={handleClose}
        />
      </div>
    </>
  );
};

export default CityEditionContainer;
