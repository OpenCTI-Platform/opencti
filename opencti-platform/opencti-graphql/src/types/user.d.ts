import type { StoreMarkingDefinition } from './store';
import type { StixId } from './stix-common';

interface UserRole {
  name: string;
}

interface UserCapability {
  name: string;
}

interface UserOrigin {
  name?: string;
  user_id?: string;
  applicant_id?: string;
  referer?: string;
}

interface AuthUser {
  id: string;
  internal_id: string;
  name: string;
  user_email: string;
  origin: Partial<UserOrigin>;
  roles: Array<UserRole>;
  organizations: Array<StixId>;
  capabilities: Array<UserCapability>;
  allowed_marking: Array<StoreMarkingDefinition>;
  all_marking: Array<StoreMarkingDefinition>;
}

interface AuthContext {
  source: string;
  tracing: TracingContext
}
