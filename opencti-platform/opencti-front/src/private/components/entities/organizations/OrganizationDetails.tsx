import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import { OrganizationDetails_organization$data } from '@components/entities/organizations/__generated__/OrganizationDetails_organization.graphql';
import { useFormatter } from '../../../../components/i18n';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

const useStyles = makeStyles(() => ({
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
    backgroundColor: 'rgba(229,152,137, 0.08)',
    color: '#e59889',
  },
}));

interface OrganizationDetailsComponentProps {
  organization: OrganizationDetails_organization$data;
}

const OrganizationDetailsComponent: FunctionComponent<OrganizationDetailsComponentProps> = ({ organization }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Organization type')}
            </Typography>
            <Chip
              classes={{ root: classes.chip }}
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
          <Grid item={true} xs={6}>
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
