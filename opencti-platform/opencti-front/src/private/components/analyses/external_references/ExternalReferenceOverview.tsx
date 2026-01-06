import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { truncate } from '../../../../utils/String';
import { ExternalReferenceOverview_externalReference$data } from './__generated__/ExternalReferenceOverview_externalReference.graphql';
import Card from '../../../../components/common/card/Card';

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
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Source name')}
            </Typography>
            {truncate(externalReference.source_name, 40)}
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Description')}
            </Typography>
            <ExpandableMarkdown
              source={externalReference.description}
              limit={400}
            />
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Original creation date')}
            </Typography>
            {fldt(externalReference.created)}
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Modification date')}
            </Typography>
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
