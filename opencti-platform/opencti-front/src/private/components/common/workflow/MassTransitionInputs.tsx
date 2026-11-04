import React, { useEffect, useRef } from 'react';
import { Formik } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS } from '../../../../utils/hooks/useGranted';
import WorkflowTransitionInputs, {
  buildTransitionInputsSchema,
  EMPTY_TRANSITION_INPUT_VALUES,
  TransitionInputRequirements,
  TransitionInputValues,
} from './WorkflowTransitionInputs';
import type { MassTransitionInputs as MassTransitionInputsValue } from './workflowMassActions';

interface MassTransitionInputsProps {
  requirements: TransitionInputRequirements;
  onChange: (inputs: MassTransitionInputsValue) => void;
}

const ReportInputs = ({ values, isValid, onChange }: { values: TransitionInputValues; isValid: boolean; onChange: MassTransitionInputsProps['onChange'] }) => {
  // The toolbar passes a new callback on each render: only a change of the inputs is reported
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;
  useEffect(() => {
    onChangeRef.current({ ...values, inputsValid: isValid });
  }, [values, isValid]);
  return null;
};

// The comment and organizations of a mass transition, collected once for every entity, with the
// fields and rules of the single-entity transition wizard
const MassTransitionInputs = ({ requirements, onChange }: MassTransitionInputsProps) => {
  const { t_i18n } = useFormatter();
  const canBypassMandatoryFields = useGranted([KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS]);
  const schema = buildTransitionInputsSchema(requirements, canBypassMandatoryFields, t_i18n);
  return (
    <Formik<TransitionInputValues> initialValues={EMPTY_TRANSITION_INPUT_VALUES} validationSchema={schema} onSubmit={() => {}}>
      {({ values }) => (
        <div className="flex flex-col gap-6">
          {/* Checked synchronously: Formik reports a form as valid until its first validation run */}
          <ReportInputs values={values} isValid={schema.isValidSync(values)} onChange={onChange} />
          <WorkflowTransitionInputs requirements={requirements} canBypassMandatoryFields={canBypassMandatoryFields} commentLength={values.comment.length} />
        </div>
      )}
    </Formik>
  );
};

export default MassTransitionInputs;
