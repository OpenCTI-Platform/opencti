import type { StixContainer } from '../../../../types/stix-2-0-sdo';

export interface StixFeedback extends StixContainer {
  name: string,
  description: string,
  rating: number,
}
