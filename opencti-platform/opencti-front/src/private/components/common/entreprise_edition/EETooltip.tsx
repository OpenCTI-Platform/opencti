import { useFormatter } from '../../../../components/i18n';
import FeedbackCreation from '../../cases/feedbacks/FeedbackCreation';
import EETooltipBase, { EETooltipBaseProps } from './EETooltipBase';

// The Enterprise Edition gate: a non-admin gets the feedback form to request the feature
const EETooltip = ({ title, ...props }: Omit<EETooltipBaseProps, 'renderNonAdminRequest'>) => {
  const { t_i18n } = useFormatter();
  return (
    <EETooltipBase
      {...props}
      title={title}
      renderNonAdminRequest={(open, onClose) => (
        <FeedbackCreation
          openDrawer={open}
          handleCloseDrawer={onClose}
          initialValue={{
            description: t_i18n('I would like to use a EE feature ...', {
              values: { feature: title },
            }),
          }}
        />
      )}
    />
  );
};

export default EETooltip;
