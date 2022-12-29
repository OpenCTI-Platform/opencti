import type { BasicStoreCommon, StoreMarkingDefinition } from './store';

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
  individual_id: undefined | string;
  name: string;
  user_email: string;
  inside_platform_organization: boolean;
  origin: Partial<UserOrigin>;
  roles: Array<UserRole>;
  organizations: Array<BasicStoreCommon>;
  allowed_organizations: Array<BasicStoreCommon>;
  capabilities: Array<UserCapability>;
  allowed_marking: Array<StoreMarkingDefinition>;
  all_marking: Array<StoreMarkingDefinition>;
}

interface AuthContext {
  source: string;
  tracing: TracingContext
  user: AuthUser | undefined;
}
