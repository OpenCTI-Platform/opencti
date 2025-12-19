import React, { FunctionComponent } from 'react';
import { useNavigate } from 'react-router-dom';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import { Typography } from '@mui/material';
import { IndicatorDetails_indicator$data } from '@components/observations/indicators/__generated__/IndicatorDetails_indicator.graphql';
import { SETTINGS_SETCUSTOMIZATION } from '../../../../utils/hooks/useGranted';
import { useFormatter } from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import Alert from '../../../../components/Alert';
import Security from '../../../../utils/Security';

interface DecayExclusionDialogContentProps {
  indicator: IndicatorDetails_indicator$data;
  onClose: () => void;
}

const DecayExclusionDialogContent: FunctionComponent<DecayExclusionDialogContentProps> = ({ indicator, onClose }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();

  const handleClick = () => {
    const link = resolveLink('DecayRule') ?? '';
    onClose();
    navigate(link, { state: { decayTab: 'decayExclusionRule' } });
  };

  return (
    <>
      <DialogTitle style={{ display: 'flex', justifyContent: 'space-between' }}>
        {t_i18n('Lifecycle details')}
        <div>{indicator.decay_exclusion_applied_rule?.decay_exclusion_name ?? ''}</div>
      </DialogTitle>
      <DialogContent>
        <Typography>{t_i18n('This indicator is currently impacted by a Decay Exclusion Rule.')}</Typography>
        <Typography>{t_i18n('This mean that the indicator is not managed by the platform.')}</Typography>
        <Typography style={{ marginTop: 20 }}>{t_i18n('Please contact your administrator to have more details about this rule & why this indicator is impacted.')}</Typography>
        <Alert
          content={t_i18n('This IOC might be impacted by an Exclusion Rule with criteria not matching anymore this IOC: once a rule is applied to an IOC, the rule does not change.')}
          severity="warning"
          style={{
            marginTop: 40,
          }}
        />
      </DialogContent>
      <DialogActions>
        <Security needs={[SETTINGS_SETCUSTOMIZATION]}>
          <Button color="secondary" onClick={handleClick}>{t_i18n('View rule')}</Button>
        </Security>
        <Button onClick={onClose}>
          {t_i18n('Close')}
        </Button>
      </DialogActions>
    </>
  );
};

export default DecayExclusionDialogContent;
