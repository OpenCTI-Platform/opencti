import { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import Chip from '@mui/material/Chip';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import ItemReliability from '../../../../components/ItemReliability';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { SettingsOrganizationDetails_organization$key } from './__generated__/SettingsOrganizationDetails_organization.graphql';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';

const styles = makeStyles<Theme>((theme) => ({
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
    width: 150,
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text?.primary,
  },
}));

const SettingsOrganizationDetailsFragment = graphql`
      fragment SettingsOrganizationDetails_organization on Organization {
        id
        description
        contact_information
        x_opencti_reliability
        x_opencti_organization_type
        objectLabel {
          edges {
            node {
              id
              value
              color
            }
          }
        }
      }
    `;

interface SettingsOrganizationDetailsProps {
  settingsOrganizationFragment: SettingsOrganizationDetails_organization$key;

}

const SettingsOrganizationDetails: FunctionComponent<
SettingsOrganizationDetailsProps
> = ({ settingsOrganizationFragment }) => {
  const { t } = useFormatter();
  const classes = styles();
  // TODO don't use useFragment again and use the object instead
  const organization = useFragment(
    SettingsOrganizationDetailsFragment,
    settingsOrganizationFragment,
  );

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Basic information')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Organization type')}
            </Typography>
            <Chip
              classes={{ root: classes.chip }}
              label={t(
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
              {t('Description')}
            </Typography>
            <ExpandableMarkdown
              source={organization.description}
              limit={400}
            />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t('Contact information')}
            </Typography>
            <Markdown
              remarkPlugins={[remarkGfm, remarkParse]}
              className="markdown"
            >
              {organization.contact_information ?? ''}
            </Markdown>
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default SettingsOrganizationDetails;
