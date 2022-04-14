import { StixCoreObject, StixId } from './stix-common';

// stream
interface Event {
  version: string;
  type: string;
  origin: string;
  markings: Array<StixId>;
  message: string;
  commit: {
    message: string | undefined;
    references: Array<string>;
  };
  data: StixCoreObject;
}

interface RuntimeEvent extends Event {
  eventId: string;
}

interface StreamEvent {
  id: string;
  event: 'update' | 'create' | 'delete';
  data: Event
}
