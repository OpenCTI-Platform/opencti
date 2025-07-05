// STIX 2.0
import type { StixContainer } from '../../../types/stix-2-0-sdo';

export interface StixGrouping extends StixContainer {
  name: string;
  description: string;
  context: string;
}
