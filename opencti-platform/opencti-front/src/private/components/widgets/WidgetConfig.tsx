import React, { FunctionComponent, useState } from 'react';
import { v4 as uuid } from 'uuid';
import WidgetCreationTypes from '@components/widgets/WidgetCreationTypes';
import WidgetCreationPerspective from '@components/widgets/WidgetCreationPerspective';
import WidgetCreationDataSelection from '@components/widgets/WidgetCreationDataSelection';
import WidgetCreationParameters from '@components/widgets/WidgetCreationParameters';
import MenuItem from '@mui/material/MenuItem';
import WidgetUpsert from '@components/widgets/WidgetUpsert';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import type { Widget } from '../../../utils/widget/widget';
import { WidgetPerspective } from './widgetUtils';

interface WidgetConfigProps {
  onComplete: (value: Widget) => void,
  open: boolean,
  setOpen: (open: boolean) => void,
  closeMenu?: () => void,
  widget?: Widget,
}

const WidgetConfig: FunctionComponent<WidgetConfigProps> = ({
  onComplete,
  closeMenu,
  widget,
  setOpen,
  open,
}) => {
  let initialStep = 0;
  if (widget?.type === 'text') {
    initialStep = 3;
  } else if (widget?.dataSelection) {
    initialStep = 2;
  }
  const { t_i18n } = useFormatter();
  const [stepIndex, setStepIndex] = useState(initialStep);
  const [type, setType] = useState<string | null>(widget?.type ?? null);
  const [perspective, setPerspective] = useState(widget?.perspective ?? null);
  const initialSelection = {
    label: '',
    attribute: 'entity_type',
    date_attribute: 'created_at',
    perspective: null,
    isTo: true,
    filters: emptyFilterGroup,
    dynamicFrom: emptyFilterGroup,
    dynamicTo: emptyFilterGroup,
  };
  const [dataSelection, setDataSelection] = useState(
    widget?.dataSelection ?? [initialSelection],
  );
  const [parameters, setParameters] = useState(widget?.parameters ?? {});

  const handleCloseAfterCancel = () => {
    if (!widget) {
      setStepIndex(0);
      setType(null);
      setPerspective(null);
      setDataSelection([initialSelection]);
      setParameters({});
    } else if (widget.type === 'text') {
      setStepIndex(3);
    } else {
      setStepIndex(2);
    }
    setOpen(false);
    setDataSelection(widget?.dataSelection ?? [initialSelection]);
  };

  const handleCloseAfterUpdate = () => {
    if (!widget) {
      setStepIndex(0);
      setType(null);
      setPerspective(null);
      setDataSelection([initialSelection]);
      setParameters({});
    } else if (widget.type === 'text') {
      setStepIndex(3);
    } else {
      setStepIndex(2);
    }
    setOpen(false);
  };
  const completeSetup = () => {
    if (type) {
      onComplete({
        ...(widget ?? {}),
        id: widget?.id ?? uuid(),
        type,
        perspective,
        dataSelection,
        parameters,
      });
    }
    handleCloseAfterUpdate();
  };
  const handleSelectType = (selectedType: string) => {
    setType(selectedType);
    if (selectedType === 'text') {
      setStepIndex(3);
    } else {
      setStepIndex(1);
    }
  };
  const handleSelectPerspective = (selectedPerspective: WidgetPerspective) => {
    const newDataSelection = dataSelection.map((n) => ({
      ...n,
      perspective: selectedPerspective,
      filters: selectedPerspective === n.perspective ? n.filters : emptyFilterGroup,
      dynamicFrom: selectedPerspective === n.perspective ? n.dynamicFrom : emptyFilterGroup,
      dynamicTo: selectedPerspective === n.perspective ? n.dynamicTo : emptyFilterGroup,
    }));
    setDataSelection(newDataSelection);
    setPerspective(selectedPerspective);
    setStepIndex(2);
  };

  const isDataSelectionAttributesValid = () => {
    for (const n of dataSelection) {
      if (n.attribute?.length === 0) {
        return false;
      }
    }
    return true;
  };
  const getStepContent = () => {
    switch (stepIndex) {
      case 0:
        return <WidgetCreationTypes handleSelectType={handleSelectType} />;
      case 1:
        return <WidgetCreationPerspective handleSelectPerspective={handleSelectPerspective} type={type as string} />;
      case 2:
        return <WidgetCreationDataSelection
          dataSelection={dataSelection}
          setDataSelection={setDataSelection}
          perspective={perspective as WidgetPerspective}
          type={type as string}
          setStepIndex={setStepIndex}
               />;
      case 3:
        return <WidgetCreationParameters
          dataSelection={dataSelection}
          setDataSelection={setDataSelection}
          parameters={parameters}
          setParameters={setParameters}
          type={type as string}
               />;
      default:
        return <div>${t_i18n('This step is not implemented')}</div>;
    }
  };
  return (
    <>
      {widget && (
        <MenuItem
          onClick={() => {
            closeMenu?.();
            setOpen(true);
          }}
        >
          {t_i18n('Update')}
        </MenuItem>
      )}
      <WidgetUpsert
        open={open}
        handleCloseAfterCancel={handleCloseAfterCancel}
        stepIndex={stepIndex}
        setStepIndex={setStepIndex}
        getStepContent={getStepContent}
        completeSetup={completeSetup}
        isDataSelectionAttributesValid={isDataSelectionAttributesValid}
        widget={widget}
        type={type}
      />
    </>
  );
};

export default WidgetConfig;
