import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import CustomFieldValuesDisplay from '@components/common/custom_fields/CustomFieldValuesDisplay';
import Card from '@common/card/Card';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import MarkdownDisplay from '../../../../components/markdownDisplay/MarkdownDisplay';
import Label from '../../../../components/common/label/Label';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { SYSTEM_ASSET_VOCABULARY_FIELDS } from './SystemAssetFields';

class SystemDetailsComponent extends Component {
  render() {
    const { t, system } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Card title={t('Details')}>
          <Grid container={true} spacing={3}>
            <Grid size={12}>
              <Label>
                {t('Description')}
              </Label>
              <ExpandableMarkdown source={system.description} limit={400} />
            </Grid>
            <Grid size={6}>
              <Label>
                {t('Reliability')}
              </Label>
              <ItemOpenVocab
                displayMode="chip"
                type="reliability_ov"
                value={system.x_opencti_reliability}
              />
              <Label sx={{ marginTop: 2 }}>
                {t('Contact information')}
              </Label>
              <MarkdownDisplay
                content={system.contact_information}
                remarkGfmPlugin={true}
                commonmark={true}
              />
            </Grid>
            <Grid size={6}>
              {SYSTEM_ASSET_VOCABULARY_FIELDS.map(({ name, type, label }, index) => (
                <React.Fragment key={name}>
                  <Label sx={index > 0 ? { marginTop: 2 } : undefined}>
                    {t(label)}
                  </Label>
                  <ItemOpenVocab
                    displayMode="chip"
                    type={type}
                    value={system[name]}
                  />
                </React.Fragment>
              ))}
              <Label sx={{ marginTop: 2 }}>
                {t('Owner')}
              </Label>
              <FieldOrEmpty source={system.x_opencti_owner}>
                {system.x_opencti_owner}
              </FieldOrEmpty>
            </Grid>
            <CustomFieldValuesDisplay entityType={system.entity_type} values={system.customFieldValues ?? []} />
          </Grid>
        </Card>
      </div>
    );
  }
}

SystemDetailsComponent.propTypes = {
  system: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
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
      x_opencti_asset_category
      x_opencti_asset_subcategory
      x_opencti_internet_facing
      x_opencti_criticality
      x_opencti_environment
      x_opencti_owner
      x_opencti_platform
    }
  `,
});

export default compose(inject18n)(SystemDetails);
