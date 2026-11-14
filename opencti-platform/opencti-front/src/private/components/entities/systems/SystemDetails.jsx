import React from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import CustomFieldValuesDisplay from '@components/common/custom_fields/CustomFieldValuesDisplay';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import MarkdownDisplay from '../../../../components/markdownDisplay/MarkdownDisplay';
import Label from '../../../../components/common/label/Label';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { vocabularyValueLabel } from '../../../../utils/vocabulary/vocabularyDisplay';

// The signals a reader acts on come first, as a posture row; the classification after
const POSTURE_FIELDS = [
  { name: 'x_opencti_criticality', type: 'system_criticality_ov', label: 'Criticality' },
  { name: 'x_opencti_internet_facing', type: 'system_internet_facing_ov', label: 'Internet facing' },
  { name: 'x_opencti_environment', type: 'system_environment_ov', label: 'Environment' },
];

export const systemFieldsNotSet = (system) => [
  ...POSTURE_FIELDS.map(({ name, label }) => ({ name, label })),
  { name: 'x_opencti_system_category', label: 'System category' },
  { name: 'x_opencti_platform', label: 'Platform' },
  { name: 'x_opencti_owner', label: 'Asset owner' },
].filter(({ name }) => !system[name]);

const SystemDetailsComponent = ({ system }) => {
  const { t_i18n } = useFormatter();
  const posture = POSTURE_FIELDS.filter(({ name }) => system[name]);
  const notSet = systemFieldsNotSet(system);
  const hasClassification = system.x_opencti_system_category || system.x_opencti_platform || system.x_opencti_owner;
  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={3}>
          {posture.length > 0 && (
            <Grid size={12} data-testid="system-posture">
              <Grid container={true} spacing={3}>
                {posture.map(({ name, type, label }) => (
                  <Grid key={name} size={{ xs: 12, md: 4 }}>
                    <Label>{t_i18n(label)}</Label>
                    <ItemOpenVocab displayMode="chip" humanLabel={true} type={type} value={system[name]} />
                  </Grid>
                ))}
              </Grid>
            </Grid>
          )}
          {hasClassification && (
            <Grid size={12} data-testid="system-classification">
              <Grid container={true} spacing={3}>
                {system.x_opencti_system_category && (
                  <Grid size={{ xs: 12, md: 4 }}>
                    <Label>{t_i18n('Type')}</Label>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <ItemOpenVocab displayMode="chip" humanLabel={true} type="system_category_ov" value={system.x_opencti_system_category} />
                      {system.x_opencti_system_subcategory && (
                        <Typography variant="body2" component="span">
                          {vocabularyValueLabel(system.x_opencti_system_subcategory, t_i18n)}
                        </Typography>
                      )}
                    </div>
                  </Grid>
                )}
                {system.x_opencti_platform && (
                  <Grid size={{ xs: 12, md: 4 }}>
                    <Label>{t_i18n('Platform')}</Label>
                    <ItemOpenVocab displayMode="chip" humanLabel={true} type="system_platform_ov" value={system.x_opencti_platform} />
                  </Grid>
                )}
                {system.x_opencti_owner && (
                  <Grid size={{ xs: 12, md: 4 }}>
                    <Label>{t_i18n('Asset owner')}</Label>
                    <Typography variant="body2">{system.x_opencti_owner}</Typography>
                  </Grid>
                )}
              </Grid>
            </Grid>
          )}
          <Grid size={12}>
            <Label>{t_i18n('Description')}</Label>
            <ExpandableMarkdown source={system.description} limit={400} />
          </Grid>
          <Grid size={{ xs: 12, md: 6 }}>
            <Label>{t_i18n('Reliability')}</Label>
            <ItemOpenVocab displayMode="chip" type="reliability_ov" value={system.x_opencti_reliability} />
          </Grid>
          <Grid size={{ xs: 12, md: 6 }}>
            <Label>{t_i18n('Contact information')}</Label>
            <FieldOrEmpty source={system.contact_information}>
              <MarkdownDisplay content={system.contact_information} remarkGfmPlugin={true} commonmark={true} />
            </FieldOrEmpty>
          </Grid>
          {notSet.length > 0 && (
            <Grid size={12} data-testid="system-fields-not-set">
              <Typography variant="body2" color="text.secondary">
                {t_i18n('{count, plural, one {# asset field not set} other {# asset fields not set}}', { values: { count: notSet.length } })}
                {': '}
                {notSet.map(({ label }) => t_i18n(label)).join(', ')}
              </Typography>
            </Grid>
          )}
          <CustomFieldValuesDisplay entityType={system.entity_type} values={system.customFieldValues ?? []} />
        </Grid>
      </Card>
    </div>
  );
};

SystemDetailsComponent.propTypes = {
  system: PropTypes.object,
};

const SystemDetails = createFragmentContainer(SystemDetailsComponent, {
  system: graphql`
    fragment SystemDetails_system on System {
      id
      entity_type
      customFieldValues {
        ...CustomFieldValuesDisplay_values @relay(mask: false)
      }
      contact_information
      description
      x_opencti_reliability
      x_opencti_system_category
      x_opencti_system_subcategory
      x_opencti_internet_facing
      x_opencti_criticality
      x_opencti_environment
      x_opencti_owner
      x_opencti_platform
    }
  `,
});

export default SystemDetails;
