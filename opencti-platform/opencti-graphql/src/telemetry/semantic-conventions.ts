import {
  ATTR_ENDUSER_ID as INCUBATING_ATTR_ENDUSER_ID,
  ATTR_MESSAGING_MESSAGE_BODY_SIZE as INCUBATING_ATTR_MESSAGING_MESSAGE_BODY_SIZE,
} from '@opentelemetry/semantic-conventions/incubating';

// This file lists all unstable OPTL semantic conventions constants used in the
// codebase. We follow the recommandation for handling such "incubating" cases
// of not using values directly imported from the /incubating entry-point but
// we still do a type verification to detect if/when a breaking change happens
// upstream:
// https://github.com/open-telemetry/opentelemetry-js/blob/main/semantic-conventions/README.md#unstable-semconv

export const ATTR_ENDUSER_ID = 'enduser.id' satisfies typeof INCUBATING_ATTR_ENDUSER_ID;
export const ATTR_MESSAGING_MESSAGE_BODY_SIZE = 'messaging.message.body.size' satisfies typeof INCUBATING_ATTR_MESSAGING_MESSAGE_BODY_SIZE;
