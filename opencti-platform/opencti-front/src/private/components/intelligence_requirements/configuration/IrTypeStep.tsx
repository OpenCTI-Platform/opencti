import React from 'react';
import { Input, Radio, RadioGroup, Text, Textarea } from '@filigran/design-system';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../../components/i18n';
import { IR_PRIORITIES, priorityLabel } from '../IntelligenceRequirementsCards';
import { IrMultiSelect, IrSelect } from './IrFields';
import { IR_PIR_TYPES, type IrPirType } from './irPresetRules';
import useSchema from '../../../../utils/hooks/useSchema';
import type { IrPresetGeneral } from './irPresetDraft';
import type { IrPriority } from './irConfigTypes';

interface IrTypeStepProps {
  general: IrPresetGeneral;
  pirType: IrPirType | null;
  flags: string[];
  onChange: (p: { general?: IrPresetGeneral; pirType?: IrPirType; flags?: string[] }) => void;
  showErrors?: boolean; // after the user tried to go to the next step
}

// Step 1 of the creation wizard: what the requirement is, and which type of PIR it is
const IrTypeStep = ({ general, pirType, flags, onChange, showErrors = false }: IrTypeStepProps) => {
  const { t_i18n } = useFormatter();
  const { schema } = useSchema();
  // A threat custom requirement can flag any entity of the platform: domain objects (containers included) and
  // observables. Relationships, sightings, meta objects (labels, markings...) and internal objects are not entities to flag.
  const flagOptions = [...schema.sdos, ...schema.scos]
    .map((type) => ({ value: type.id, label: t_i18n(`entity_${type.id}`) }))
    .sort((a, b) => a.label.localeCompare(b.label));
  const setGeneral = (patch: Partial<IrPresetGeneral>) => onChange({ general: { ...general, ...patch } });
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <Box sx={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 2, alignItems: 'end' }}>
        <Input
          label={t_i18n('Name')}
          required
          value={general.name}
          onChange={(e) => setGeneral({ name: e.target.value })}
          error={showErrors && !general.name.trim() ? t_i18n('This field is required') : undefined}
        />
        <IrSelect
          label={t_i18n('Priority')}
          value={general.priority}
          options={IR_PRIORITIES.map((p) => ({ value: p, label: priorityLabel(t_i18n, p) }))}
          onChange={(v) => setGeneral({ priority: v as IrPriority })}
        />
      </Box>
      <Textarea
        label={t_i18n('Intelligence question')}
        required
        value={general.question}
        onChange={(e) => setGeneral({ question: e.target.value })}
        error={showErrors && !general.question.trim() ? t_i18n('This field is required') : undefined}
      />
      <Box>
        <Text as="div" variant="title-sm" id="ir-pir-type-label" style={{ marginBottom: 12 }}>{t_i18n('PIR type')}</Text>
        <RadioGroup
          aria-labelledby="ir-pir-type-label"
          value={pirType ?? ''}
          onValueChange={(v) => onChange({ pirType: v as IrPirType })}
          style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}
        >
          {IR_PIR_TYPES.map((type) => (
            <Box
              key={type.key}
              sx={{
                border: '1px solid',
                borderColor: pirType === type.key ? 'primary.main' : 'divider',
                borderRadius: 1,
                p: 2,
              }}
            >
              <Radio
                value={type.key}
                disabled={!type.enabled}
                label={t_i18n(type.label)}
                description={type.enabled ? t_i18n(type.description) : `${t_i18n(type.description)} ${t_i18n('Rules not defined yet')}`}
              />
            </Box>
          ))}
        </RadioGroup>
        {showErrors && !pirType && (
          <Text as="p" variant="content-caption" style={{ marginTop: 8 }}>
            <Box component="span" sx={{ color: 'error.main' }}>{t_i18n('Choose a PIR type')}</Box>
          </Text>
        )}
      </Box>
      {pirType === 'threat_custom' && (
        <Box sx={{ maxWidth: 640 }}>
          <IrMultiSelect
            label={t_i18n('Flagged types')}
            values={flags}
            options={flagOptions}
            onChange={(next) => onChange({ flags: next })}
            placeholder={t_i18n('Add…')}
          />
          {showErrors && flags.length === 0 && (
            <Text as="p" variant="content-caption" style={{ marginTop: 8 }}>
              <Box component="span" sx={{ color: 'error.main' }}>{t_i18n('Choose at least one type to flag')}</Box>
            </Text>
          )}
        </Box>
      )}
    </Box>
  );
};

export default IrTypeStep;
