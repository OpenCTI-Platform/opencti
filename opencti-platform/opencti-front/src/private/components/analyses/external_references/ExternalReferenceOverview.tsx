import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { truncate } from '../../../../utils/String';
import { ExternalReferenceOverview_externalReference$data } from './__generated__/ExternalReferenceOverview_externalReference.graphql';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';

interface ExternalReferenceOverviewComponentProps {
  externalReference: ExternalReferenceOverview_externalReference$data;
}

const ExternalReferenceOverviewComponent: FunctionComponent<
  ExternalReferenceOverviewComponentProps
> = ({ externalReference }) => {
  const { t_i18n, fldt } = useFormatter();

  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Overview')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Source name')}
            </Label>
            {truncate(externalReference.source_name, 40)}
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Description')}
            </Label>
            <ExpandableMarkdown
              source={externalReference.description}
              limit={400}
            />
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Original creation date')}
            </Label>
            {fldt(externalReference.created)}
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Modification date')}
            </Label>
            {fldt(externalReference.modified)}
          </Grid>
        </Grid>
      </Card>
    </div>
  );
};

const ExternalReferenceOverview = createFragmentContainer(
  ExternalReferenceOverviewComponent,
  {
    externalReference: graphql`
      fragment ExternalReferenceOverview_externalReference on ExternalReference {
        id
        source_name
        description
        url
        created
        modified
      }
    `,
  },
);

export default ExternalReferenceOverview;
