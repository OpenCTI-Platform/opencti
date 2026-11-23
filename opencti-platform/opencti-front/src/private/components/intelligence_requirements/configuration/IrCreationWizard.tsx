import React, { useState } from 'react';
import { Paper } from '@filigran/design-system';
import Box from '@mui/material/Box';
// FDS gap: the design system has no stepper yet
import Stepper from '@mui/material/Stepper';
import Step from '@mui/material/Step';
import StepLabel from '@mui/material/StepLabel';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import IntelligenceRequirementConfigurationForm from './IntelligenceRequirementConfigurationForm';
import IrTypeStep from './IrTypeStep';
import IrRulesStep from './IrRulesStep';
import { IR_PIR_TYPES, type IrPirType } from './irPresetRules';
import { presetItemsToDraft, validatePresetItems, type IrPresetGeneral, type IrPresetItem } from './irPresetDraft';
import { writeConfigView } from './irSentence';

const emptyGeneral = (): IrPresetGeneral => ({ name: '', question: '', description: '', priority: 'medium' });

/**
 * Creation of a requirement: pick a PIR type (step 1), build its criteria from the type's preset rules (step 2),
 * then review the requirement in the configuration form, scoring included (step 3).
 */
const IrCreationWizard = () => {
  const { t_i18n } = useFormatter();
  const [step, setStep] = useState(0);
  const [general, setGeneral] = useState<IrPresetGeneral>(emptyGeneral);
  const [pirType, setPirType] = useState<IrPirType | null>(null);
  const [customFlags, setCustomFlags] = useState<string[]>([]); // the flagged types of a "Threat custom" requirement
  const [items, setItems] = useState<IrPresetItem[]>([]);
  const [renamed, setRenamed] = useState<Set<string>>(() => new Set());
  const [triedNext, setTriedNext] = useState<boolean[]>([false, false]);
  const [reviewKey, setReviewKey] = useState(0); // remounts the form each time the review step opens
  const steps = [t_i18n('General settings'), t_i18n('Criteria'), t_i18n('Scoring and review')];

  const flags = pirType === 'threat_custom' ? customFlags : (IR_PIR_TYPES.find((p) => p.key === pirType)?.flags ?? []);
  const canLeave = (index: number) => {
    if (index === 0) return !!general.name.trim() && !!pirType && flags.length > 0;
    if (index === 1) return validatePresetItems(items).length === 0;
    return true;
  };
  const next = () => {
    if (!canLeave(step)) {
      setTriedNext((tried) => tried.map((v, i) => (i === step ? true : v)));
      return;
    }
    if (step === 1) setReviewKey((k) => k + 1);
    setStep(step + 1);
  };

  return (
    <Box sx={{ maxWidth: step === 2 ? undefined : 1100 }}>
      <Stepper activeStep={step} sx={{ mb: 3, maxWidth: 1100 }}>
        {steps.map((label) => (
          <Step key={label}>
            <StepLabel>{label}</StepLabel>
          </Step>
        ))}
      </Stepper>
      {step === 0 && (
        <Paper padding={24}>
          <IrTypeStep
            general={general}
            pirType={pirType}
            flags={customFlags}
            showErrors={triedNext[0]}
            onChange={(p) => {
              if (p.general) setGeneral(p.general);
              if (p.flags) setCustomFlags(p.flags);
              if (p.pirType && p.pirType !== pirType) {
                // the rules of a type do not carry over to another one
                setPirType(p.pirType);
                setItems([]);
                setRenamed(new Set());
                setTriedNext((tried) => [tried[0], false]);
              }
            }}
          />
        </Paper>
      )}
      {step === 1 && pirType && (
        <Paper padding={24}>
          <IrRulesStep
            pirType={pirType}
            flags={flags}
            items={items}
            onChange={setItems}
            renamed={renamed}
            onRenamedChange={setRenamed}
            showErrors={triedNext[1]}
          />
        </Paper>
      )}
      {step === 2 && pirType && (
        <IntelligenceRequirementConfigurationForm
          key={reviewKey}
          initialDraft={presetItemsToDraft(general, pirType, flags, items)}
          view="fields"
          onCreated={(id) => writeConfigView(id, 'fields')}
        />
      )}
      <Box sx={{ display: 'flex', gap: 1, mt: 2, maxWidth: 1100 }}>
        {step > 0 && <Button variant="secondary" onClick={() => setStep(step - 1)}>{t_i18n('Back')}</Button>}
        <Box sx={{ flex: 1 }} />
        {step < steps.length - 1 && <Button onClick={next}>{t_i18n('Next')}</Button>}
      </Box>
    </Box>
  );
};

export default IrCreationWizard;
