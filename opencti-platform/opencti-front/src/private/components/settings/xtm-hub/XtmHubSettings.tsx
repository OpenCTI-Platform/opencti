import { graphql, useLazyLoadQuery } from 'react-relay';
import React from 'react';
import Paper from '@mui/material/Paper';
import { Grid2, List, ListItem, ListItemText, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
import Box from '@mui/material/Box';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import XtmHubTab from './XtmHubTab';
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

  const isEnrolled = xtmHubSettings.xtm_hub_enrollment_status === 'enrolled';

  return (
    <section>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Settings') },
          { label: t_i18n('XTM Hub'), current: true },
        ]}
      />
      <Grid2 container spacing={3}>
        <Grid2 size={6}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('XTM Hub Enrollment')}
          </Typography>
          <div
            style={{
              float: 'right',
              marginTop: theme.spacing(-4.5),
              position: 'relative',
            }}
          >
            <XtmHubTab
              enrollmentStatus={
                xtmHubSettings.xtm_hub_enrollment_status || undefined
              }
            />
          </div>
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
              <Typography variant="h6" sx={{ marginBottom: 1 }}>
                {t_i18n(
                  'XTM Hub is the focal point to find every Services and Products.',
                )}
              </Typography>
              {t_i18n("By enrolling your OpenCTI instance, you'll be able to:")}
              <List sx={{ listStyleType: 'disc', marginLeft: 4, marginTop: 1 }}>
                <li>
                  {t_i18n(
                    'deploy in one-click Threats intelligence ressources',
                  )}
                </li>
                <li>{t_i18n('see metrics on your instance')}</li>
              </List>
            </Box>
            <List style={{ marginTop: -10 }}>
              {isEnrolled && (
                <>
                  <ListItem divider={true}>
                    <ListItemText primary={t_i18n('Enrollment status')} />
                    <ItemBoolean
                      variant="large"
                      label={t_i18n('Enrolled')}
                      status={true}
                    />
                  </ListItem>
                  <ListItem divider={true}>
                    <ListItemText primary={t_i18n('Enrollment date')} />
                    <ItemBoolean
                      variant="large"
                      neutralLabel={dateFormat(
                        xtmHubSettings.xtm_hub_enrollment_date,
                      )}
                      status={null}
                    />
                  </ListItem>
                  <ListItem divider={true}>
                    <ListItemText primary={t_i18n('Enrolled by')} />
                    <ItemBoolean
                      variant="large"
                      neutralLabel={xtmHubSettings.xtm_hub_enrollment_user_name}
                      status={null}
                    />
                  </ListItem>
                </>
              )}
              {!isEnrolled && (
                <ListItem divider={true}>
                  <ListItemText primary={t_i18n('Enrollment status')} />
                  <ItemBoolean
                    variant="large"
                    label={t_i18n('Not enrolled')}
                    status={false}
                  />
                </ListItem>
              )}
            </List>
          </Paper>
        </Grid2>
      </Grid2>
    </section>
  );
};

export default XtmHubSettings;
