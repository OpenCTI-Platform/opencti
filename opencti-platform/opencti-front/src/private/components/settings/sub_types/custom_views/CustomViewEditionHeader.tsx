import { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Box, Tooltip } from '@mui/material';
import Button from '@common/button/Button';
import Tag from '@common/tag/Tag';
import { useTheme } from '@mui/styles';
import VisibilityIcon from '@mui/icons-material/Visibility';
import VisibilityOffIcon from '@mui/icons-material/VisibilityOff';
import TitleMainEntity from '../../../../../components/common/typography/TitleMainEntity';
import { CustomViewEditionHeader_customView$key } from './__generated__/CustomViewEditionHeader_customView.graphql';
import Breadcrumbs from '../../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../../components/i18n';
import CustomViewFormDrawer from './CustomViewFormDrawer';
import useEntityTranslation from '../../../../../utils/hooks/useEntityTranslation';
import DashboardWidgetConfig from 'src/components/dashboard/DashboardWidgetConfig';
import type { Widget } from '../../../../../utils/widget/widget';
import CustomViewMenu from './CustomViewMenu';
import type { Theme } from '../../../../../components/Theme';
import useCustomViewEdit from './useCustomViewEdit';

const headerFragment = graphql`
  fragment CustomViewEditionHeader_customView on CustomView {
    id
    name
    description
    targetEntityType
    enabled
    ...CustomViewMenu_customView
  }
`;

interface CustomViewEditionHeaderProps {
  data: CustomViewEditionHeader_customView$key;
  onImportWidget: (widgetFile: File) => void;
  onCreateWidget: (value: Widget, variableName?: string) => void;
}

const CustomViewEditionHeader = ({ data, onCreateWidget, onImportWidget }: CustomViewEditionHeaderProps) => {
  const { t_i18n } = useFormatter();
  const { translateEntityType } = useEntityTranslation();
  const [isFormOpen, setFormOpen] = useState(false);
  const customView = useFragment(headerFragment, data);
  const theme = useTheme<Theme>();
  const [commitCustomViewMutation, mutating] = useCustomViewEdit();
  const customizationLink = '/dashboard/settings/customization/entity_types';
  const subTypeLink = `${customizationLink}/${customView.targetEntityType}/custom-views`;
  const breadcrumb = [
    { label: t_i18n('Settings') },
    { label: t_i18n('Customization') },
    { label: t_i18n('Entity types'), link: customizationLink },
    { label: translateEntityType(customView.targetEntityType), link: subTypeLink },
    { label: t_i18n('Custom Views') },
    { label: customView.name },
  ];
  const handleToggleEnabled = () => {
    commitCustomViewMutation({
      variables: {
        id: customView.id,
        input: [{
          key: 'enabled',
          value: [!customView.enabled],
        }],
      },
    });
  };
  return (
    <>
      <Breadcrumbs elements={breadcrumb} />

      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
        <TitleMainEntity>{customView.name}</TitleMainEntity>
        <Tag
          color={
            customView.enabled
              ? theme.palette.severity.low
              : theme.palette.severity.critical
          }
          label={
            customView.enabled
              ? t_i18n('View is enabled')
              : t_i18n('View is disabled')
          }
          labelTextTransform="none"
        />
        <Box sx={{ display: 'flex', alignItems: 'center', marginLeft: 'auto', gap: 1 }}>
          <Tooltip title={customView.enabled ? t_i18n('Disable') : t_i18n('Enable')}>
            <Button variant="secondary" iconOnly disabled={mutating} onClick={handleToggleEnabled}>
              {customView.enabled ? <VisibilityOffIcon /> : <VisibilityIcon />}
            </Button>
          </Tooltip>
          <CustomViewMenu data={customView} />
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
        entityType={customView.targetEntityType}
        isOpen={isFormOpen}
        onClose={() => setFormOpen(false)}
        customView={customView}
      />
    </>
  );
};

export default CustomViewEditionHeader;
