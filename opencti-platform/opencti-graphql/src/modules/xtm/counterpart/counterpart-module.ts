import type { ModuleDescriptor } from '../../module-descriptor';
import counterpartTypeDefs from './core/counterpart.graphql';
import counterpartResolvers from './core/counterpart-resolver';
import { registerCounterpartProvider } from './core/counterpart-domain';
import { xtmOneProvider } from './xtmone/xtmone-provider';
import { openAevProvider } from './openaev/openaev-provider';
import { openCrqProvider } from './opencrq/opencrq-provider';

// The order is the order of the answers and of the emblems (Contract v3: XTM One, OpenAEV, OpenCRQ)
const COUNTERPART_PROVIDERS = [xtmOneProvider, openAevProvider, openCrqProvider];

const xtmCounterpartModule: ModuleDescriptor = {
  id: 'xtmCounterpart',
  graphqlSchemas: [{ schema: counterpartTypeDefs, resolver: counterpartResolvers }],
  // The registry of the domain, read at request time only
  init: () => COUNTERPART_PROVIDERS.forEach((provider) => registerCounterpartProvider(provider)),
};

export default xtmCounterpartModule;
