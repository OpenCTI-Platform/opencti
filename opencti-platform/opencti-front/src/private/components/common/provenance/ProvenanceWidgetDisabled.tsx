import React, { ReactNode } from 'react';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { Widget } from '../../../../utils/widget/widget';
import { PROVENANCE_WIDGET_DISABLED, PROVENANCE_WIDGET_TITLES } from './provenanceWidgetUtils';

interface ProvenanceWidgetDisabledProps {
  widget: Widget;
  popover?: ReactNode;
}

/**
 * Takes the place of a provenance widget saved on a dashboard while provenance is disabled: the widget keeps its
 * place and its actions, and no provenance query runs.
 */
const ProvenanceWidgetDisabled = ({ widget, popover }: ProvenanceWidgetDisabledProps) => {
  const { t_i18n } = useFormatter();
  return (
    <WidgetContainer
      padding="small"
      title={widget.parameters?.title ?? t_i18n(PROVENANCE_WIDGET_TITLES[widget.type])}
      action={popover}
    >
      <WidgetNoData message={t_i18n(PROVENANCE_WIDGET_DISABLED)} />
    </WidgetContainer>
  );
};

export default ProvenanceWidgetDisabled;
