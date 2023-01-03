import type { BasicStoreCommon, BasicStoreObject, StoreMarkingDefinition } from './store';

interface UserRole extends BasicStoreObject {
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

interface AuthUser extends BasicStoreObject {
  id: string;
  internal_id: string;
  individual_id: string | undefined;
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
  api_token: string;
}

interface AuthContext {
  source: string;
  tracing: TracingContext
  user: AuthUser | undefined;
}
