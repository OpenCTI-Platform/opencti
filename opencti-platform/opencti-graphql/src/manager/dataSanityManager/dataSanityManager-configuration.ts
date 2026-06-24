import type { AuthContext } from '../../types/user';
import { fakeFixForPoc } from '../../modules/dataSanity/fixes/fakeFixForPoc';

// run_once: executes only once, then never again
// on_demand: executes only when force_run is set to true in the DataSanity entity
// periodic: executes on every manager run
type ExecutionType = 'run_once' | 'on_demand' | 'periodic';

export interface SanityFixOutput {
  message: string;
}

export interface SanityFix {
  name: string; // unique name to identify the sanity function
  execution_type: ExecutionType;
  fn: (context: AuthContext) => Promise<SanityFixOutput>; // the data sanity function
}

const SANITY_FIXES: SanityFix[] = [
  {
    name: 'fakeFixForPoc', // FIXME POC hack
    fn: fakeFixForPoc,
    execution_type: 'run_once',
  },
];

export const sanityFixList = () => {
  return SANITY_FIXES;
};
