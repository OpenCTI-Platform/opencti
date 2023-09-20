import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import InfrastructureEditionOverview from './InfrastructureEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { Theme } from '../../../../components/Theme';
import { InfrastructureEditionContainerQuery } from './__generated__/InfrastructureEditionContainerQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';

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

export const infrastructureEditionContainerQuery = graphql`
  query InfrastructureEditionContainerQuery($id: String!) {
    infrastructure(id: $id) {
      ...InfrastructureEditionOverview_infrastructure
      editContext {
        name
        focusOn
      }
    }
  }
`;

interface InfrastructureEditionContainerProps {
  handleClose: () => void;
  queryRef: PreloadedQuery<InfrastructureEditionContainerQuery>;
}

const InfrastructureEditionContainer: FunctionComponent<InfrastructureEditionContainerProps> = ({ handleClose, queryRef }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const queryData = usePreloadedQuery(infrastructureEditionContainerQuery, queryRef);

  if (queryData.infrastructure) {
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
            {t('Update an infrastructure')}
          </Typography>
          <SubscriptionAvatars context={queryData.infrastructure.editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <InfrastructureEditionOverview
            infrastructureData={queryData.infrastructure}
            enableReferences={useIsEnforceReference('Infrastructure')}
            context={queryData.infrastructure.editContext}
            handleClose={handleClose}
          />
        </div>
      </div>
    );
  }

  return <Loader variant={LoaderVariant.inElement} />;
};

export default InfrastructureEditionContainer;
