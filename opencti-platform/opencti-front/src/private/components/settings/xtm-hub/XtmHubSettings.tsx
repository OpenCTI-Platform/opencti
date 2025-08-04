import { graphql, useLazyLoadQuery } from 'react-relay';
import React from 'react';
import Paper from '@mui/material/Paper';
import { Grid2, List, ListItem, ListItemText, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
import Box from '@mui/material/Box';
import XtmHubTab from '@components/settings/xtm-hub/XtmHubTab';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import { XtmHubSettingsQuery } from './__generated__/XtmHubSettingsQuery.graphql';
import { dateFormat } from '../../../../utils/Time';
import ItemBoolean from '../../../../components/ItemBoolean';

export const xtmHubSettingsQuery = graphql`
  query XtmHubSettingsQuery {
    settings {
      id
      xtm_hub_enrollment_date
      xtm_hub_enrollment_status
      xtm_hub_enrollment_user_id
      xtm_hub_enrollment_user_name
      xtm_hub_last_connectivity_check
      xtm_hub_token
    }
  }
`;

const XtmHubSettings = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { settings: xtmHubSettings } = useLazyLoadQuery<XtmHubSettingsQuery>(
    xtmHubSettingsQuery,
    {},
  );

  return (
    <section>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Settings') },
          { label: t_i18n('XTM Hub'), current: true },
        ]}
      />
      <Grid2 container spacing={3}>
        <Grid2 size={7}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('XTM Hub Registration')}
          </Typography>
          <div className="clearfix" />
          <Paper
            className="paper-for-grid"
            variant="outlined"
            sx={{
              height: '100%',
              minHeight: '100%',
              margin: '10px 0 0 0',
              padding: '15px',
              borderRadius: 1,
              marginTop: '4px',
            }}
          >
            <Box
              sx={{
                color: theme.palette.text.disabled,
                marginBottom: 2,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1em' }}>
                <Typography variant="h6">
                  {t_i18n(
                    'XTM Hub is the focal point to find every Services and Products.',
                  )}
                </Typography>
                <XtmHubTab
                  enrollmentStatus={
                    xtmHubSettings.xtm_hub_enrollment_status || undefined
                  }
                />
              </div>
              {t_i18n("By registering your OpenCTI platform, you'll be able to:")}
              <List sx={{ listStyleType: 'disc', marginLeft: 4, marginTop: 1 }}>
                <li>
                  {t_i18n(
                    'deploy in one-click Threats Intelligence Resources',
                  )}
                </li>
                <li>{t_i18n('see metrics on your platform')}</li>
              </List>
            </Box>
            <List style={{ marginTop: -10 }}>
              {
                xtmHubSettings.xtm_hub_enrollment_status === 'enrolled' && (
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
                        neutralLabel={dateFormat(
                          xtmHubSettings.xtm_hub_enrollment_date,
                          'DD MMM YYYY',
                        )}
                        status={null}
                      />
                    </ListItem>
                    <ListItem divider={true}>
                      <ListItemText primary={t_i18n('Registered by')} />
                      <ItemBoolean
                        variant="xlarge"
                        neutralLabel={xtmHubSettings.xtm_hub_enrollment_user_name}
                        status={null}
                      />
                    </ListItem>
                  </>
                )
              }
              {
                xtmHubSettings.xtm_hub_enrollment_status === 'lost_connectivity' && (
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
                        neutralLabel={dateFormat(
                          xtmHubSettings.xtm_hub_last_connectivity_check,
                          'DD MMM YYYY',
                        )}
                        status={null}
                      />
                    </ListItem>
                  </>
                )
              }
              {
                xtmHubSettings.xtm_hub_enrollment_status === 'unenrolled' && (
                  <ListItem divider={true}>
                    <ListItemText primary={t_i18n('Registration status')} />
                    <ItemBoolean
                      variant="xlarge"
                      label={t_i18n('Not registered')}
                      status={false}
                    />
                  </ListItem>
                )
              }
            </List>
          </Paper>
        </Grid2>
      </Grid2>
    </section>
  );
};

export default XtmHubSettings;
