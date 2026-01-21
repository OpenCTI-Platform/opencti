import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import SubTypeMenu from './SubTypeMenu';
import { useParams } from 'react-router-dom';
import Card from '@common/card/Card';
import TitleMainEntity from '@common/typography/TitleMainEntity';
import Grid from '@mui/material/Grid2';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import CustomizationMenu from '../CustomizationMenu';

const SubTypeWorkflow = () => {
  const { t_i18n } = useFormatter();
  const { subTypeId = '' } = useParams<{ subTypeId: string }>();
  return (
    <div style={{ margin: 0, padding: '0 200px 50px 0' }}>
      <Breadcrumbs elements={[
        { label: t_i18n('Settings') },
        { label: t_i18n('Customization') },
        { label: t_i18n('Entity types'), link: '/dashboard/settings/customization/entity_types' },
        { label: t_i18n(`entity_${subTypeId}`), current: true },
      ]}
      />

      <CustomizationMenu />

      <SubTypeMenu entityType={subTypeId} />

      <TitleMainEntity sx={{ mb: 3 }}>
        {t_i18n(`entity_${subTypeId}`)}
      </TitleMainEntity>

      <Grid container spacing={3}>

        <Grid size={{ xs: 12 }} gap={3}>
          <Card>
            {/* TODO Workflow settings component */}
            <div>Workflow settings component</div>
          </Card>
        </Grid>
      </Grid>
    </div>
  );
};

export default SubTypeWorkflow;
