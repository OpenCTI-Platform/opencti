import React, { FunctionComponent } from 'react';
import Grid from '@mui/material/Grid';
import { DraftRootFragment$data } from '@components/drafts/__generated__/DraftRootFragment.graphql';
import Label from '@common/label/Label';
import ExpandableMarkdown from '../../../components/ExpandableMarkdown';
import { truncate } from '../../../utils/String';
import { useFormatter } from '../../../components/i18n';
import Card from '@common/card/Card';

interface DraftDetailsProps {
  draft: DraftRootFragment$data;
}

const DraftDetails: FunctionComponent<DraftDetailsProps> = ({ draft }) => {
  const { t_i18n } = useFormatter();

  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Overview')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Name')}
            </Label>
            {truncate(draft.name, 40)}
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Description')}
            </Label>
            <ExpandableMarkdown
              source={draft.description}
              limit={400}
            />
          </Grid>
        </Grid>
      </Card>
    </div>
  );
};

export default DraftDetails;
