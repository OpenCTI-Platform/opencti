import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import { OrganizationDetails_organization$data } from '@components/entities/organizations/__generated__/OrganizationDetails_organization.graphql';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ItemScore from '../../../../components/ItemScore';

interface OrganizationDetailsComponentProps {
  organization: OrganizationDetails_organization$data;
}

const OrganizationDetailsComponent: FunctionComponent<OrganizationDetailsComponentProps> = ({ organization }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Details')}
      </Typography>
      <Paper
        style={{
          marginTop: theme.spacing(1),
          padding: '15px',
          borderRadius: 6,
        }}
        className={'paper-for-grid'}
        variant="outlined"
      >
        <Grid container={true} spacing={3}>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Organization type')}
            </Typography>
            <Chip
              style={{
                fontSize: 12,
                height: 25,
                marginRight: 7,
                textTransform: 'uppercase',
                borderRadius: 4,
                width: 150,
                backgroundColor: 'rgba(229,152,137, 0.08)',
                color: '#e59889',
              }}
              label={organization.x_opencti_organization_type || t_i18n('Unknown')}
            />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={fieldSpacingContainerStyle}
            >
              {t_i18n('Description')}
            </Typography>
            <ExpandableMarkdown
              source={organization.description}
              limit={400}
            />
          </Grid>
          <Grid item xs={6}>
            <Typography
              variant="h3"
              gutterBottom={true}
            >
              {t_i18n('Contact information')}
            </Typography>
            <MarkdownDisplay
              content={organization.contact_information ?? ''}
              remarkGfmPlugin={true}
              commonmark={true}
            />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Score')}
            </Typography>
            <ItemScore score={organization.x_opencti_score} />
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

const OrganizationDetails = createFragmentContainer(
  OrganizationDetailsComponent,
  {
    organization: graphql`
        fragment OrganizationDetails_organization on Organization {
            id
            description
            contact_information
            x_opencti_score
            x_opencti_organization_type
            objectLabel {
                id
                value
                color
            }
        }
    `,
  },
);

export default OrganizationDetails;
