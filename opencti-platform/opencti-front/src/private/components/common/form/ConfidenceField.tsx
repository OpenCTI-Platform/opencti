import React, { FunctionComponent } from 'react';
import { Field } from 'formik';
import Alert from '@mui/material/Alert';
import ConfidenceInputSliderField from '../../../../components/ConfidenceInputSliderField';
import { useFormatter } from '../../../../components/i18n';
import { GenericContext } from '../model/GenericContextModel';
import { layerInputVars } from '../../../../utils/fdsLayer';
import useConfidenceLevel from '../../../../utils/hooks/useConfidenceLevel';

interface ConfidenceFieldProps {
  name?: string;
  label?: string;
  variant?: string;
  showAlert?: boolean;
  onSubmit?: (name: string, value: string) => void;
  onFocus?: (name: string, value: string) => void;
  editContext?: readonly (GenericContext | null)[] | null;
  containerStyle?: Record<string, string | number>;
  entityType?: string;
  disabled?: boolean;
  custom_max_level?: number;
  helperText?: string;
  disableTopMargin?: boolean;
}

const ConfidenceField: FunctionComponent<ConfidenceFieldProps> = ({
  name = 'confidence',
  label,
  variant,
  showAlert = true,
  onFocus,
  onSubmit,
  editContext,
  containerStyle,
  entityType,
  disabled,
  custom_max_level,
  helperText,
  disableTopMargin = false,
}) => {
  const { t_i18n } = useFormatter();
  const finalLabel = label || t_i18n('Confidence level');
  const { getEffectiveConfidenceLevel } = useConfidenceLevel();
  const userEffectiveMaxConfidence = custom_max_level ?? getEffectiveConfidenceLevel(entityType);

  const Slider = (
    <Field
      component={ConfidenceInputSliderField}
      variant={variant}
      containerstyle={containerStyle}
      fullWidth={true}
      entityType={entityType}
      attributeName={name}
      name={name}
      label={finalLabel}
      onFocus={onFocus}
      onSubmit={onSubmit}
      editContext={editContext}
      disabled={disabled}
      maxLimit={userEffectiveMaxConfidence}
      helperText={helperText}
    />
  );

  return showAlert ? (
    <Alert
      severity="info"
      icon={false}
      variant="outlined"
      // The alias ladder is anchored by the host panel; the block sits one step above it.
      className="layer-3"
      aria-label={finalLabel}
      sx={{
        position: 'relative',
        width: '100%',
        marginTop: disableTopMargin ? 0 : '20px',
        padding: '16px',
        border: 'none',
        borderRadius: 'var(--radius-sm)',
        backgroundColor: 'var(--bg-elevation-default)',
        // `--bg-input-default` resolves where it is DECLARED, on `:root`, so the layer class alone misses it.
        ...layerInputVars,
        // The alert's own message slot leads with 8px, which stacked on the padding above.
        '& .MuiAlert-message': {
          width: '100%',
          overflow: 'visible',
          padding: 0,
        },
      }}
    >
      {Slider}
    </Alert>
  ) : Slider;
};

export default ConfidenceField;
