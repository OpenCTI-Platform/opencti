import React, { ReactNode } from 'react';
import WidgetContainer from '../../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../../components/dashboard/WidgetNoData';
import { useFormatter } from '../../../../../components/i18n';
import useGranted, { KNOWLEDGE } from '../../../../../utils/hooks/useGranted';

interface DefenseWidgetContainerProps {
  title: string;
  popover?: ReactNode;
  /** The content that loads the widget data, mounted only for a reader of the knowledge */
  children: ReactNode;
}

/**
 * The frame of a defense widget. The defense queries need the knowledge access, which a dashboard editor may not have:
 * the widget then says so, and keeps its menu so that it can still be removed.
 */
const DefenseWidgetContainer = ({ title, popover, children }: DefenseWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const canReadKnowledge = useGranted([KNOWLEDGE]);
  return (
    <WidgetContainer title={title} action={popover}>
      {canReadKnowledge ? children : <WidgetNoData message={t_i18n('You do not have any access to the knowledge of this OpenCTI instance.')} />}
    </WidgetContainer>
  );
};

export default DefenseWidgetContainer;
