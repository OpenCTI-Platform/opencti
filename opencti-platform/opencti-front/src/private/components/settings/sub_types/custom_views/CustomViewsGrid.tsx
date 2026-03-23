import { useFormatter } from '../../../../../components/i18n';
import React, { useState } from 'react';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import { Add as AddIcon } from '@mui/icons-material';
import CustomViewsLines from '@components/settings/sub_types/custom_views/CustomViewsLines';
import { graphql, useFragment } from 'react-relay';
import { CustomViewsGrid_customViews$data, CustomViewsGrid_customViews$key } from '@components/settings/sub_types/custom_views/__generated__/CustomViewsGrid_customViews.graphql';

export type CustomViewType
  = NonNullable<CustomViewsGrid_customViews$data['custom_views_info']>;

const customViewsFragment = graphql`
  fragment CustomViewsGrid_customViews on CustomViewsSettings {
    can_have_custom_views
    custom_views_info {
      id
      name
      description
      created_at
      updated_at
    }
  }
`;

interface CustomViewsGridProps {
  data: CustomViewsGrid_customViews$key;
}

const CustomViewsGrid = ({ data }: CustomViewsGridProps) => {
  const { t_i18n } = useFormatter();
  const [dataTableRef, setDataTableRef] = useState<HTMLDivElement | null>(null);

  const dataResolved = useFragment(customViewsFragment, data);
  const { custom_views_info } = dataResolved;

  return (
    <Grid item xs={12}>
      <Card
        title={t_i18n('Custom Views')}
        action={(
          <Tooltip title={t_i18n('Create a new custom view')}>
            <IconButton size="small">
              <AddIcon fontSize="small" color="primary" />
            </IconButton>
          </Tooltip>
        )}
      >
        <div
          style={{ height: '100%', width: '100%' }}
          ref={(r) => setDataTableRef(r)}
        >
          <CustomViewsLines
            customViews={custom_views_info}
            dataTableRef={dataTableRef}
          />
        </div>
      </Card>
    </Grid>
  );
};

export default CustomViewsGrid;
