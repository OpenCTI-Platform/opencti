import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import { OrganizationDetails_organization$data } from '@components/entities/organizations/__generated__/OrganizationDetails_organization.graphql';
import { useTheme } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useAuth from '../../../../utils/hooks/useAuth';
import type { Theme } from '../../../../components/Theme';

interface OrganizationDetailsComponentProps {
  organization: OrganizationDetails_organization$data;
}

const OrganizationDetailsComponent: FunctionComponent<OrganizationDetailsComponentProps> = ({ organization }) => {
  const { me: { monochrome_labels } } = useAuth();
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Details')}
      </Typography>
      <Paper
        className={'paper-for-grid'}
        variant="outlined"
        style={{
          marginTop: theme.spacing(1),
          padding: theme.spacing(2),
          borderRadius: 4,
        }}
      >
        <Grid container={true} spacing={3}>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Organization type')}
            </Typography>
            <Chip
              label={organization.x_opencti_organization_type || t_i18n('Unknown')}
              style={{
                fontSize: 12,
                height: 25,
                marginRight: 7,
                textTransform: 'uppercase',
                borderRadius: 4,
                width: 150,
                backgroundColor: monochrome_labels ? theme.palette.background.accent : 'rgba(229,152,137, 0.08)',
                color: theme.palette.chip.main,
              }}
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
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Reliability')}
            </Typography>
            <ItemOpenVocab
              displayMode="chip"
              type="reliability_ov"
              value={organization.x_opencti_reliability}
            />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={fieldSpacingContainerStyle}
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

const OrganizationDetails = createFragmentContainer(
  OrganizationDetailsComponent,
  {
    organization: graphql`
        fragment OrganizationDetails_organization on Organization {
            id
            description
            contact_information
            x_opencti_reliability
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
