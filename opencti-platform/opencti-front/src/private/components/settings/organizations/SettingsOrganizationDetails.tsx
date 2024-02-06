import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import Chip from '@mui/material/Chip';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import { SettingsOrganization_organization$data } from './__generated__/SettingsOrganization_organization.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 4,
  },
  chip: {
    fontSize: 12,
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: '0',
    width: 150,
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text?.primary,
  },
}));

interface SettingsOrganizationDetailsProps {
  settingsOrganization: SettingsOrganization_organization$data;
}

const SettingsOrganizationDetails: FunctionComponent<
SettingsOrganizationDetailsProps
> = ({ settingsOrganization }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const organization = settingsOrganization;
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Basic information')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Organization type')}
            </Typography>
            <Chip
              classes={{ root: classes.chip }}
              label={t_i18n(
                organization.x_opencti_organization_type
                  ? `organization_${organization.x_opencti_organization_type}`
                  : 'organization_other',
              )}
            />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Description')}
            </Typography>
            <ExpandableMarkdown source={organization.description} limit={400} />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Contact information')}
            </Typography>
            <MarkdownDisplay
              content={organization.contact_information ?? ''}
              remarkGfmPlugin={true}
              commonmark={true}
            />
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default SettingsOrganizationDetails;
