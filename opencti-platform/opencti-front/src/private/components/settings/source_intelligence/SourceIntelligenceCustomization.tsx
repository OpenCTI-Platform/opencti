import React from 'react';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import PageContainer from '../../../../components/PageContainer';
import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import SourceIntelligenceSettings from '../../integrations/sources/SourceIntelligenceSettings';

/** Source Intelligence computation, value weights, recommendation thresholds, tuning, autonomy and gap settings. */
const SourceIntelligenceCustomization = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Source intelligence | Customization | Settings'));
  return (
    <div data-testid="source-intelligence-settings-page">
      <PageContainer withGap withRightMenu>
        <Breadcrumbs
          noMargin
          elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Customization') }, { label: t_i18n('Source intelligence'), current: true }]}
        />
        <SourceIntelligenceSettings />
      </PageContainer>
    </div>
  );
};

export default SourceIntelligenceCustomization;
