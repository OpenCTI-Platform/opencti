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

// A bouger dans CustomViewForm.tsx
export interface CustomViewFormInputs {
  name: string;
  description: string | null;
  published: boolean;
}

export type CustomViewType = NonNullable<CustomViewsGrid_customViews$data['customViews']>['edges'][0]['node'];

const customViewsFragment = graphql`
  fragment CustomViewsGrid_customViews on EntitySetting {
    id
    target_type
    customViews (orderBy: name, orderMode: asc) {
      edges {
        node {
          id
          name
          description
        }
      }
    }
  }
`;

interface CustomViewsGridProps {
  data: CustomViewsGrid_customViews$key;
}

const CustomViewsGrid = ({ data }: CustomViewsGridProps) => {
  const { t_i18n } = useFormatter();
  const [dataTableRef, setDataTableRef] = useState<HTMLDivElement | null>(null);
  const [isDrawerOpen, setDrawerOpen] = useState(false);
  const [customViewToEdit, setcustomViewToEdit] = useState<{ id: string } & CustomViewFormInputs>();

  const dataResolved = useFragment(customViewsFragment, data);
  if (!dataResolved) return null;
  const { target_type, customViews, id: entitySettingId } = dataResolved;

  // const onUpdate = (customView: CustomViewType) => {
  //   setcustomViewToEdit({
  //     id: customView.id,
  //     name: customView.name,
  //     description: customView.description ?? null,
  //   });
  //   setDrawerOpen(true);
  // };

  return (
    <>
      <Grid item xs={12}>
        <Card
          title={t_i18n('Custom Views')}
          action={(
            <div>
              <Tooltip title={t_i18n('Create a new custom view')}>
                <IconButton
                  onClick={() => setDrawerOpen(true)}
                  size="small"
                >
                  <AddIcon fontSize="small" color="primary" />
                </IconButton>
              </Tooltip>
            </div>
          )}
        >
          <div style={{ height: '100%', width: '100%' }} ref={(r) => setDataTableRef(r)}>
            <CustomViewsLines
              customViews={customViews}
              dataTableRef={dataTableRef}
              // onUpdate={onUpdate}
              entitySettingId={entitySettingId}
              targetType={target_type}
            />
          </div>
        </Card>
      </Grid>
      {/* <CustomViewFormDrawer */}
      {/*  entitySettingId={entitySettingId} */}
      {/*  isOpen={isDrawerOpen} */}
      {/*  customView={customViewToEdit} */}
      {/*  entityType={target_type} */}
      {/*  onClose={() => { */}
      {/*    setDrawerOpen(false); */}
      {/*    setcustomViewToEdit(undefined); */}
      {/*  }} */}
      {/* /> */}
    </>
  );
};

export default CustomViewsGrid;
