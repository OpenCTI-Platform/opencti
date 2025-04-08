import type { StixDomainObject2 } from './stix-2-0-common';
import type { StixId, StixDate, StixKillChainPhase } from './stix-2-1-common';

export interface StixMalware2 extends StixDomainObject2 {
  name: string; // optional
  description: string; // optional
  malware_types: Array<string>; // optional
  is_family: boolean;
  aliases: Array<string>; // optional
  kill_chain_phases: Array<StixKillChainPhase>; // optional
  first_seen: StixDate; // optional
  last_seen: StixDate; // optional
  architecture_execution_envs: Array<string>; // optional
  implementation_languages: Array<string>; // optional
  capabilities: Array<string>; // optional
  operating_system_refs: Array<StixId>; // optional
  sample_refs: Array<StixId>; // optional
  samples: { id: string }[]; // optional
}
