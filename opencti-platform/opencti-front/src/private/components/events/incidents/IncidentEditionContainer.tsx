import React, { FunctionComponent, useState } from 'react';
import {
  createFragmentContainer,
  graphql,
  PreloadedQuery,
  usePreloadedQuery,
} from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import IncidentEditionOverview from './IncidentEditionOverview';
import IncidentEditionDetails from './IncidentEditionDetails';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { IncidentEditionContainerQuery } from './__generated__/IncidentEditionContainerQuery.graphql';

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
  title: {
    float: 'left',
  },
}));

interface IncidentEditionContainerProps {
  queryRef: PreloadedQuery<IncidentEditionContainerQuery>;
  handleClose: () => void;
}

export const IncidentEditionQuery = graphql`
  query IncidentEditionContainerQuery($id: String!) {
    incident(id: $id) {
      ...IncidentEditionOverview_incident
      ...IncidentEditionDetails_incident
      ...IncidentDetails_incident
      editContext {
        name
        focusOn
      }
    }
  }
`;

const IncidentEditionContainer: FunctionComponent<
IncidentEditionContainerProps
> = ({ queryRef, handleClose }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const queryData = usePreloadedQuery(IncidentEditionQuery, queryRef);
  const [currentTab, setCurrentTab] = useState(0);
  const handleChangeTab = (event: React.SyntheticEvent, value: number) => setCurrentTab(value);

  if (queryData.incident === null) {
    return <ErrorNotFound />;
  }
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
          {t('Update an incident')}
        </Typography>
        <SubscriptionAvatars context={queryData.incident.editContext} />
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
          <IncidentEditionOverview
            incidentRef={queryData.incident}
            enableReferences={useIsEnforceReference('Incident')}
            context={queryData.incident.editContext}
            handleClose={handleClose}
          />
        )}
        {currentTab === 1 && (
          <IncidentEditionDetails
            incidentRef={queryData.incident}
            enableReferences={useIsEnforceReference('Incident')}
            context={queryData.incident.editContext}
            handleClose={handleClose}
          />
        )}
      </div>
    </div>
  );
};

const IncidentEditionContainerFragment = createFragmentContainer(
  IncidentEditionContainer,
  {
    incident: graphql`
      fragment IncidentEditionContainer_incident on Incident {
        id
        ...IncidentEditionOverview_incident
        ...IncidentEditionDetails_incident
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default IncidentEditionContainerFragment;
