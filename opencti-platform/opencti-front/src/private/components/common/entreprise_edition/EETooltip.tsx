import { useFormatter } from '../../../../components/i18n';
import FeedbackCreation from '../../cases/feedbacks/FeedbackCreation';
import EETooltipBase, { EETooltipBaseProps } from './EETooltipBase';
import { EERequest } from './EERequestContext';

const FeedbackRequest = ({ open, onClose, feature }: { open: boolean; onClose: () => void; feature?: string }) => {
  const { t_i18n } = useFormatter();
  return (
    <FeedbackCreation
      openDrawer={open}
      handleCloseDrawer={onClose}
      initialValue={{
        description: t_i18n('I would like to use a EE feature ...', {
          values: { feature },
        }),
      }}
    />
  );
};

export const renderFeedbackRequest: EERequest = (open, onClose, feature) => (
  <FeedbackRequest open={open} onClose={onClose} feature={feature} />
);

// The Enterprise Edition gate: a non-admin gets the feedback form to request the feature
const EETooltip = (props: Omit<EETooltipBaseProps, 'renderNonAdminRequest'>) => (
  <EETooltipBase {...props} renderNonAdminRequest={renderFeedbackRequest} />
);

export default EETooltip;
