import { ComponentType } from 'react';
import { FieldConfig, Field as FormikField } from 'formik';

export const fieldSpacingContainerStyle = { marginTop: 20, width: '100%' };

export interface FieldOption {
  id?: string;
  value: string;
  label: string;
  color?: string;
  type?: string;
  standard_id?: string;
}

// TODO move this interface inside file KillChainPhasesField
// when it has been transformed it TypeScript.
export interface KillChainPhaseFieldOption extends FieldOption {
  kill_chain_name: string;
  phase_name: string;
}

type FormikFieldConfig<P> = Omit<FieldConfig<P>, 'component' | 'as' | 'render' | 'children'>;
type NoMetaProps<P> = Omit<P, 'field' | 'form' | 'meta'>;
type FieldProps<ComponentProps> = FormikFieldConfig<ComponentProps> & NoMetaProps<ComponentProps> & {
  component: ComponentType<ComponentProps>;
};

const Field = <C extends object>(props: FieldProps<C>) => {
  return <FormikField {...props} />;
};

export default Field;
