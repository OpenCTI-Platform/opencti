import React, { ReactNode } from 'react';
import { Button, Text } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import type { Widget } from '../../../../utils/widget/widget';
import type { Theme } from '../../../../components/Theme';
import { PROVENANCE_CONFIGURATION_DOCUMENTATION, PROVENANCE_WIDGET_DISABLED, PROVENANCE_WIDGET_DISABLED_NEXT_STEP, PROVENANCE_WIDGET_TITLES } from './provenanceWidgetUtils';

interface ProvenanceWidgetDisabledProps {
  widget: Widget;
  popover?: ReactNode;
}

/**
 * Takes the place of a provenance widget saved on a dashboard while provenance is disabled: the widget keeps its
 * place and its actions, says how to enable provenance, and no provenance query runs.
 */
const ProvenanceWidgetDisabled = ({ widget, popover }: ProvenanceWidgetDisabledProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  return (
    <WidgetContainer
      padding="small"
      title={widget.parameters?.title ?? t_i18n(PROVENANCE_WIDGET_TITLES[widget.type])}
      action={popover}
    >
      <div
        data-testid="provenance-widget-disabled"
        style={{
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: theme.spacing(1),
          textAlign: 'center',
        }}
      >
        <Text variant="content-base">{t_i18n(PROVENANCE_WIDGET_DISABLED)}</Text>
        <Text variant="content-caption">{t_i18n(PROVENANCE_WIDGET_DISABLED_NEXT_STEP)}</Text>
        <Button priority="tertiary" size="sm" asChild>
          <a href={PROVENANCE_CONFIGURATION_DOCUMENTATION} target="_blank" rel="noreferrer">{t_i18n('Learn more')}</a>
        </Button>
      </div>
    </WidgetContainer>
  );
};

export default ProvenanceWidgetDisabled;
