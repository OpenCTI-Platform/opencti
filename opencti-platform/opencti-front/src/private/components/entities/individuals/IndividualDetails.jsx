import React from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import Label from '../../../../components/common/label/Label';
import Tag from '../../../../components/common/tag/Tag';

const IndividualDetailsComponent = (props) => {
  const { t_i18n } = useFormatter();
  const { individual } = props;
  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={12}>
            <Label>
              {t_i18n('Description')}
            </Label>
            <ExpandableMarkdown source={individual.description} limit={400} />
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Reliability')}
            </Label>
            <ItemOpenVocab
              displayMode="chip"
              type="reliability_ov"
              value={individual.x_opencti_reliability}
            />
            <Label sx={{ marginTop: 2 }}>
              {t_i18n('Contact information')}
            </Label>
            <FieldOrEmpty source={individual.contact_information}>
              <Tag label={individual.contact_information} />
            </FieldOrEmpty>
          </Grid>
        </Grid>
      </Card>
    </div>
  );
};

IndividualDetailsComponent.propTypes = {
  individual: PropTypes.object,
};

const IndividualDetails = createFragmentContainer(IndividualDetailsComponent, {
  individual: graphql`
    fragment IndividualDetails_individual on Individual {
      id
      contact_information
      description
      x_opencti_reliability
    }
  `,
});

export default IndividualDetails;
