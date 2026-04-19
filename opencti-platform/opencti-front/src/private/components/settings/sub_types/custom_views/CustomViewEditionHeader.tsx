import { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Box, Typography } from '@mui/material';
import Button from '@common/button/Button';
import { CustomViewEditionHeader_customView$key } from './__generated__/CustomViewEditionHeader_customView.graphql';
import Breadcrumbs from '../../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../../components/i18n';
import CustomViewFormDrawer from './CustomViewFormDrawer';
import useEntityTranslation from '../../../../../utils/hooks/useEntityTranslation';
import DashboardWidgetConfig from 'src/components/dashboard/DashboardWidgetConfig';
import type { DashboardWidget } from '../../../../../components/dashboard/dashboard-types';
import CustomViewKebabMenu from './CustomViewKebabMenu';
// import ExportButtons from 'src/components/ExportButtons';

const headerFragment = graphql`
  fragment CustomViewEditionHeader_customView on CustomView {
    id
    name
    description
    target_entity_type
    ...CustomViewKebabMenu_customView
  }
`;

interface CustomViewEditionHeaderProps {
  data: CustomViewEditionHeader_customView$key;
  onImportWidget: (widgetFile: File) => void;
  onCreateWidget: (value: DashboardWidget, variableName?: string) => void;
}

const CustomViewEditionHeader = ({ data, onCreateWidget, onImportWidget }: CustomViewEditionHeaderProps) => {
  const { t_i18n } = useFormatter();
  const { translateEntityType } = useEntityTranslation();
  const [isFormOpen, setFormOpen] = useState(false);

  useEntityTranslation();
  const customView = useFragment(headerFragment, data);
  const customizationLink = '/dashboard/settings/customization/entity_types';
  const subTypeLink = `${customizationLink}/${customView.target_entity_type}/custom-views`;
  const breadcrumb = [
    { label: t_i18n('Settings') },
    { label: t_i18n('Customization') },
    { label: t_i18n('Entity types'), link: customizationLink },
    { label: translateEntityType(customView.target_entity_type), link: subTypeLink },
    { label: t_i18n('Custom Views') },
    { label: customView.name },
  ];

  return (
    <>
      <Breadcrumbs elements={breadcrumb} />

      <Box sx={{ display: 'flex', gap: 1 }}>
        <Typography variant="h1" sx={{ float: 'left' }}>
          {customView.name}
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', marginLeft: 'auto', gap: 1 }}>
          {
            //  <ExportButtons
            //    domElementId="container"
            //    name={customView.name}
            //    handleExportDashboard={() => {}}
            //    exportToImage={false}
            //    exportToPdf={false}
            //  />
          }
          <CustomViewKebabMenu data={customView} />
          <DashboardWidgetConfig
            onComplete={onCreateWidget}
            handleImportWidget={onImportWidget}
          />
          <Button disableElevation onClick={() => setFormOpen(true)}>
            {t_i18n('Update')}
          </Button>
        </Box>
      </Box>

      <CustomViewFormDrawer
        entityType={customView.target_entity_type}
        isOpen={isFormOpen}
        onClose={() => setFormOpen(false)}
        customView={customView}
      />
    </>
  );
};

export default CustomViewEditionHeader;
