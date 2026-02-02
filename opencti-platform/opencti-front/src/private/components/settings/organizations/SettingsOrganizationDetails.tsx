import React, { FunctionComponent } from 'react';
import Grid from '@mui/material/Grid';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import { SettingsOrganization_organization$data } from './__generated__/SettingsOrganization_organization.graphql';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import Tag from '@common/tag/Tag';

interface SettingsOrganizationDetailsProps {
  settingsOrganization: SettingsOrganization_organization$data;
}

const SettingsOrganizationDetails: FunctionComponent<
  SettingsOrganizationDetailsProps
> = ({ settingsOrganization }) => {
  const { t_i18n } = useFormatter();
  const organization = settingsOrganization;
  return (
    <Card title={t_i18n('Basic information')}>
      <Grid container={true} spacing={2}>
        <Grid item xs={12}>
          <Label>
            {t_i18n('Organization type')}
          </Label>
          <FieldOrEmpty source={organization.x_opencti_organization_type}>
            <Tag
              label={organization.x_opencti_organization_type}
            />
          </FieldOrEmpty>
          <Label
            sx={{ marginTop: 2 }}
          >
            {t_i18n('Description')}
          </Label>
          <ExpandableMarkdown source={organization.description} limit={400} />
          <Label
            sx={{ marginTop: 2 }}
          >
            {t_i18n('Contact information')}
          </Label>
          <MarkdownDisplay
            content={organization.contact_information ?? ''}
            remarkGfmPlugin={true}
            commonmark={true}
          />
        </Grid>
      </Grid>
    </Card>
  );
};

export default SettingsOrganizationDetails;
