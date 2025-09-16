import * as Yup from 'yup';

export const managerContractDefinitionSchema = Yup.object().shape({
  title: Yup.string().required(),
  slug: Yup.string().required(),
});

export type ManagerContractDefinition = Yup.InferType<typeof managerContractDefinitionSchema>;
