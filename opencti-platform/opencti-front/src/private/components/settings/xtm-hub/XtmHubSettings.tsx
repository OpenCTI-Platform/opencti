import { graphql, useLazyLoadQuery } from 'react-relay';
import React, { useEffect, useState, useContext } from 'react';
import Paper from '@mui/material/Paper';
import { List, ListItem, ListItemText, Typography } from '@mui/material';
import { Theme } from '@mui/material/styles/createTheme';
import XtmHubTab from '@components/settings/xtm-hub/XtmHubTab';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { XtmHubSettingsQuery } from './__generated__/XtmHubSettingsQuery.graphql';
import ItemBoolean from '../../../../components/ItemBoolean';
import useGranted, { SETTINGS_SETMANAGEXTMHUB } from '../../../../utils/hooks/useGranted';
import Button from '@common/button/Button';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { UserContext } from '../../../../utils/hooks/useAuth';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: 20,
    borderRadius: 4,
  },
}));

export const xtmHubSettingsQuery = graphql`
  query XtmHubSettingsQuery {
    settings {
      id
      xtm_hub_registration_date
      xtm_hub_registration_status
      xtm_hub_registration_user_id
      xtm_hub_registration_user_name
      xtm_hub_last_connectivity_check
      xtm_hub_backend_is_reachable
      xtm_hub_token
    }
  }
`;

export const checkHubConnectivity = graphql`
  mutation XtmHubSettingsCheckConnectivityMutation {
    checkXTMHubConnectivity {
      status
    }
  }
`;

const XtmHubSettingsComponent = () => {
  const { t_i18n, fd } = useFormatter();
  const classes = useStyles();
  const { settings: xtmHubSettings } = useLazyLoadQuery<XtmHubSettingsQuery>(
    xtmHubSettingsQuery,
    {},
  );
  const isGrantedToXtmHub = useGranted([SETTINGS_SETMANAGEXTMHUB]);
  const { isXTMHubAccessible } = useContext(UserContext);
  return (
    <>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
        {t_i18n('XTM Hub')}
      </Typography>
      {
        isGrantedToXtmHub
        && isXTMHubAccessible
        && xtmHubSettings.xtm_hub_backend_is_reachable
        && (<XtmHubTab registrationStatus={xtmHubSettings.xtm_hub_registration_status || undefined} />)
      }
      <div className="clearfix" />
      <Paper
        classes={{ root: classes.paper }}
        variant="outlined"
        className="paper-for-grid"
      >
        <Typography variant="h6">
          {t_i18n('Experiment valuable threat management resources in the XTM Hub')}
        </Typography>
        <p>{t_i18n("XTM Hub is a central forum to access resources, share tradecraft, and optimize the use of Filigran's products, fostering collaboration and empowering the community.")}</p>
        {xtmHubSettings.xtm_hub_registration_status !== 'registered' && xtmHubSettings.xtm_hub_registration_status !== 'lost_connectivity' && (
          <>
            <p>{t_i18n('By registering this platform into the hub, it will allow to:')}</p>
            <List sx={{ listStyleType: 'disc', marginLeft: 4 }}>
              <li>{t_i18n('deploy in one-click threat management resources such as feeds, dashboards, playbooks, etc.')}</li>
              <li>{t_i18n('stay informed of new resources and key threat events with an exclusive news feed')} <i>({t_i18n('coming soon')})</i></li>
              <li>{t_i18n('monitor key metrics of the platform and health status')} <i>({t_i18n('coming soon')})</i></li>
            </List>

            <Button
              gradient
              variant="secondary"
              component="a"
              href="https://filigran.io/platforms/xtm-hub/"
              target="_blank"
              rel="noreferrer"
              style={{ marginTop: 10, marginBottom: 10 }}
            >
              {t_i18n('Discover the Hub')}
            </Button>

          </>
        )}
        <List style={{ marginTop: -10 }}>
          {xtmHubSettings.xtm_hub_registration_status === 'registered' && (
            <>
              <ListItem divider={true}>
                <ListItemText primary={t_i18n('Registration status')} />
                <ItemBoolean
                  variant="xlarge"
                  label={t_i18n('Registered')}
                  status={true}
                />
              </ListItem>
              <ListItem divider={true}>
                <ListItemText primary={t_i18n('Registration date')} />
                <ItemBoolean
                  variant="xlarge"
                  neutralLabel={fd(xtmHubSettings.xtm_hub_registration_date)}
                  status={null}
                />
              </ListItem>
              <ListItem divider={true}>
                <ListItemText primary={t_i18n('Registered by')} />
                <ItemBoolean
                  variant="xlarge"
                  neutralLabel={xtmHubSettings.xtm_hub_registration_user_name}
                  status={null}
                />
              </ListItem>
            </>
          )}
          {xtmHubSettings.xtm_hub_registration_status === 'lost_connectivity' && (
            <>
              <ListItem divider={true}>
                <ListItemText primary={t_i18n('Registration status')} />
                <ItemBoolean
                  variant="xlarge"
                  label={t_i18n('Connectivity lost')}
                  status={false}
                />
              </ListItem>
              <ListItem divider={true}>
                <ListItemText primary={t_i18n('Last successful check')} />
                <ItemBoolean
                  variant="xlarge"
                  neutralLabel={fd(xtmHubSettings.xtm_hub_last_connectivity_check)}
                  status={null}
                />
              </ListItem>
            </>
          )}
        </List>
      </Paper>
    </>
  );
};

const XtmHubSettings: React.FC = () => {
  const [commitCheckConnectivity] = useApiMutation(checkHubConnectivity);
  const [isCheckDone, setIsCheckDone] = useState(false);

  useEffect(() => {
    commitCheckConnectivity({ variables: {},
      onCompleted: () => {
        setIsCheckDone(true);
      } });
  }, []);

  if (!isCheckDone) {
    return <Loader variant={LoaderVariant.inElement} />;
  }

  return <XtmHubSettingsComponent />;
};

export default XtmHubSettings;
