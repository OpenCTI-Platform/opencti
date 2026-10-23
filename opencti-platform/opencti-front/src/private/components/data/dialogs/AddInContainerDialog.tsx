import React, { useState } from 'react';
import DialogActions from '@mui/material/DialogActions';
import { AddOutlined } from '@mui/icons-material';
import {
  Checkbox,
  Combobox,
  ComboboxChips,
  ComboboxClear,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
  IconButton,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import StixDomainObjectCreation from '../../common/stix_domain_objects/StixDomainObjectCreation';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import { fetchContainerOptions, type StepOption } from '../dataTableToolBarStepOptions';
import type { UpdateStep } from '../dataTableToolBarUpdateSteps';

interface AddInContainerDialogProps {
  open: boolean;
  onClose: () => void;
  // The containers and options are kept by the toolbar between two openings
  step: UpdateStep;
  onStepChange: (update: (step: UpdateStep) => UpdateStep) => void;
  onLaunch: () => void;
}

const AddInContainerDialog = ({ open, onClose, step, onStepChange, onLaunch }: AddInContainerDialogProps) => {
  const { t_i18n } = useFormatter();
  const [containers, setContainers] = useState<StepOption[]>([]);
  const [creationOpen, setCreationOpen] = useState(false);

  const search = (newValue: string) => {
    const inputValue = newValue && newValue.length > 0 ? newValue : '';
    onStepChange((current) => ({ ...current, inputValue }));
    fetchContainerOptions(inputValue).then(setContainers);
  };

  const handleCreated = (data: { id: string; name: string; entity_type: string }) => {
    const element = { label: data.name, value: data.id, type: data.entity_type };
    setContainers((current) => [...current, element]);
    onStepChange((current) => ({ ...current, values: [...(current.values ?? []), element] }));
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t_i18n('Add in container')}
    >
      <StixDomainObjectCreation
        inputValue={step.inputValue || ''}
        open={creationOpen}
        display={true}
        speeddial={true}
        stixDomainObjectTypes={['Container']}
        handleClose={() => setCreationOpen(false)}
        creationCallback={handleCreated}
      />
      <Combobox<StepOption>
        selectOnFocus={true}
        getOptionLabel={(option) => (option.label ? option.label : '')}
        value={step.values || []}
        multiple={true}
        closeOnSelect
        options={containers}
        inputValue={step.inputValue || ''}
        onInputChange={(newValue, meta) => {
          if (meta.cause === 'type') search(newValue);
        }}
        onValueChange={(next, meta) => {
          if (meta.event) {
            meta.event.stopPropagation();
            meta.event.preventDefault();
          }
          onStepChange((current) => ({ ...current, values: Array.isArray(next) ? next : [next] }));
        }}
        renderOption={(option) => (
          <>
            <div style={{ paddingTop: 4, display: 'inline-block' }}>
              <ItemIcon type={option.type} />
            </div>
            <div style={{ display: 'inline-block', flexGrow: 1, marginLeft: 10 }}>{option.label}</div>
          </>
        )}
        disableClearable
      >
        <ComboboxLabel>{t_i18n('Values')}</ComboboxLabel>
        {/* The create control is interactive, so it takes the host-owned `adornment` slot. */}
        <ComboboxField adornment={(
          <Tooltip>
            <TooltipTrigger asChild>
              <IconButton
                size="sm"
                priority="tertiary"
                aria-label={t_i18n('Create container')}
                onClick={() => setCreationOpen(true)}
                icon={<AddOutlined fontSize="small" />}
              />
            </TooltipTrigger>
            <TooltipContent>{t_i18n('Create container')}</TooltipContent>
          </Tooltip>
        )}
        >
          <ComboboxChips aria-label={t_i18n('Values')} />
          <ComboboxInput onFocus={() => search('')} />
          <ComboboxControls>
            <ComboboxClear />
            <ComboboxTrigger />
          </ComboboxControls>
        </ComboboxField>
        <ComboboxContent
          emptyMessage={t_i18n('No available options')}
          listAriaLabel={t_i18n('Values')}
        />
      </Combobox>
      <div style={{ marginTop: 20 }}>
        <Checkbox
          checked={step.options?.includeNeighbours || false}
          onCheckedChange={(checked) => onStepChange((current) => ({
            ...current,
            options: { ...current.options, includeNeighbours: checked === true },
          }))}
          label={t_i18n('Also include first neighbours')}
        />
      </div>
      <DialogActions>
        <Button variant="secondary" onClick={onClose}>
          {t_i18n('Cancel')}
        </Button>
        <Button onClick={onLaunch}>
          {t_i18n('Add')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default AddInContainerDialog;
