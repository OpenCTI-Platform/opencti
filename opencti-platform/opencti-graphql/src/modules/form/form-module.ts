import type { ModuleDescriptor } from '../module-descriptor';
import { FORM_DEFINITION } from './form';
import formTypeDefs from './form.graphql';
import formResolvers from './form-resolver';

const formModule: ModuleDescriptor = {
  id: 'form',
  dataModel: [FORM_DEFINITION],
  graphqlSchemas: [{ schema: formTypeDefs, resolver: formResolvers }],
};

export default formModule;
