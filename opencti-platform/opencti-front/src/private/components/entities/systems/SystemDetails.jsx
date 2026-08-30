import React from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import MarkdownDisplay from '../../../../components/markdownDisplay/MarkdownDisplay';
import Label from '../../../../components/common/label/Label';

const SystemDetailsComponent = (props) => {
  const { t_i18n } = useFormatter();
  const { system } = props;
  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={12}>
            <Label>
              {t_i18n('Description')}
            </Label>
            <ExpandableMarkdown source={system.description} limit={400} />
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Reliability')}
            </Label>
            <ItemOpenVocab
              displayMode="chip"
              type="reliability_ov"
              value={system.x_opencti_reliability}
            />
            <Label sx={{ marginTop: 2 }}>
              {t_i18n('Contact information')}
            </Label>
            <MarkdownDisplay
              content={system.contact_information}
              remarkGfmPlugin={true}
              commonmark={true}
            />
          </Grid>
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
      contact_information
      description
      x_opencti_reliability
    }
  `,
});

export default SystemDetails;
