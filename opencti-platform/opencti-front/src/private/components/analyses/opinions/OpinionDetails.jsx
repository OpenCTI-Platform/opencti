import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import inject18n from '../../../../components/i18n';
import MarkdownDisplay from '../../../../components/markdownDisplay/MarkdownDisplay';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import Grid from '@mui/material/Grid';
import CustomFieldValuesDisplay from '@components/common/custom_fields/CustomFieldValuesDisplay';

class OpinionDetailsComponent extends Component {
  render() {
    const { t, opinion } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Card title={t('Entity details')}>
          <Grid container={true} spacing={3}>
            <Grid size={12}>
              <Label>
                {t('Opinion')}
              </Label>
              <MarkdownDisplay
                content={opinion.opinion}
                remarkGfmPlugin={true}
                commonmark={true}
              />
              <Label sx={{ mt: 2 }}>
                {t('Explanation')}
              </Label>
              <MarkdownDisplay
                content={opinion.explanation}
                remarkGfmPlugin={true}
                commonmark={true}
              />
            </Grid>
            <CustomFieldValuesDisplay entityType={opinion.entity_type} values={opinion.customFieldValues ?? []} />
          </Grid>
        </Card>
      </div>
    );
  }
}

OpinionDetailsComponent.propTypes = {
  opinion: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const OpinionDetails = createFragmentContainer(OpinionDetailsComponent, {
  opinion: graphql`
    fragment OpinionDetails_opinion on Opinion {
      id
      entity_type
      customFieldValues {
        ...CustomFieldValuesDisplay_values @relay(mask: false)
      }
      opinion
      explanation
    }
  `,
});

export default inject18n(OpinionDetails);
