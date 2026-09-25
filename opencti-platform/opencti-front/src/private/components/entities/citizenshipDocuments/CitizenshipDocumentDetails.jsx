import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import Label from '../../../../components/common/label/Label';
import Tag from '../../../../components/common/tag/Tag';

class CitizenshipDocumentDetailsComponent extends Component {
  render() {
    const { t, citizenshipDocument } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Card title={t('Details')}>
          <Grid container={true} spacing={3}>
            <Grid item xs={12}>
              <Label>
                {t('Description')}
              </Label>
              <ExpandableMarkdown source={citizenshipDocument.description} limit={400} />
            </Grid>
            <Grid item xs={6}>
              <Label>
                {t('Reliability')}
              </Label>
              <ItemOpenVocab
                displayMode="chip"
                type="reliability_ov"
                value={citizenshipDocument.x_opencti_reliability}
              />
              <Label sx={{ marginTop: 2 }}>
                {t('Doc Type')}
              </Label>
              <FieldOrEmpty source={citizenshipDocument.x_opencti_citizenship_document_type}>
                <Tag label={citizenshipDocument.x_opencti_citizenship_document_type} />
              </FieldOrEmpty>
              <Label sx={{ marginTop: 2 }}>
                {t('Doc Value')}
              </Label>
              <FieldOrEmpty source={citizenshipDocument.x_opencti_citizenship_document_id}>
                <Tag label={citizenshipDocument.x_opencti_citizenship_document_id} />
              </FieldOrEmpty>
            </Grid>
          </Grid>
        </Card>
      </div>
    );
  }
}

CitizenshipDocumentDetailsComponent.propTypes = {
  citizenshipDocument: PropTypes.object, // TODO validate this
  t: PropTypes.func,
  fld: PropTypes.func,
};

const CitizenshipDocumentDetails = createFragmentContainer(CitizenshipDocumentDetailsComponent, {
  citizenshipDocument: graphql`
    fragment CitizenshipDocumentDetails_citizenshipDocument on CitizenshipDocument {
      id
      description
      x_opencti_reliability
      x_opencti_citizenship_document_type
      x_opencti_citizenship_document_id
    }
  `,
});

export default R.compose(inject18n)(CitizenshipDocumentDetails);
