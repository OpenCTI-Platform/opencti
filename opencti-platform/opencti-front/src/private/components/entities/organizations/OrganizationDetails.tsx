import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import { OrganizationDetails_organization$key } from '@components/entities/organizations/__generated__/OrganizationDetails_organization.graphql';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import ItemScore from '../../../../components/ItemScore';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import Tag from '../../../../components/common/tag/Tag';

const organizationDetailsFragment = graphql`
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
`;

interface OrganizationDetailsComponentProps {
  organizationData: OrganizationDetails_organization$key;
}

const OrganizationDetails: FunctionComponent<OrganizationDetailsComponentProps> = ({ organizationData }) => {
  const { t_i18n } = useFormatter();
  const organization = useFragment(organizationDetailsFragment, organizationData);

  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Organization type')}
            </Label>
            <Tag
              color="#e59889"
              label={organization.x_opencti_organization_type || t_i18n('Unknown')}
            />
            <Label
              sx={{ mt: 2 }}
            >
              {t_i18n('Description')}
            </Label>
            <ExpandableMarkdown
              source={organization.description}
              limit={400}
            />
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Contact information')}
            </Label>
            <MarkdownDisplay
              content={organization.contact_information ?? ''}
              remarkGfmPlugin={true}
              commonmark={true}
            />
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Score')}
            </Label>
            <ItemScore score={organization.x_opencti_score} />
          </Grid>
        </Grid>
      </Card>
    </div>
  );
};

export default OrganizationDetails;
