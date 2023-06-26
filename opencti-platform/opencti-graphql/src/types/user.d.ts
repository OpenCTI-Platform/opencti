import type { BasicStoreCommon, BasicStoreIdentifier, StoreMarkingDefinition } from './store';
import type { Group } from './group';

interface UserRole {
  name: string;
}

interface UserCapability {
  name: string;
}

interface UserOrigin {
  socket: string;
  name?: string;
  user_id?: string;
  group_ids?: string[];
  organization_ids?: string[];
  applicant_id?: string;
  referer?: string;
}

interface AuthUser extends BasicStoreIdentifier {
  entity_type: string;
  id: string;
  internal_id: string;
  individual_id: string | undefined;
  name: string;
  user_email: string;
  inside_platform_organization: boolean;
  origin: Partial<UserOrigin>;
  roles: Array<UserRole>;
  groups: Array<Group>;
  organizations: Array<BasicStoreCommon>;
  allowed_organizations: Array<BasicStoreCommon>;
  capabilities: Array<UserCapability>;
  allowed_marking: Array<StoreMarkingDefinition>;
  default_marking?: Array<{ entity_type: string, values: Array<StoreMarkingDefinition> }>;
  all_marking: Array<StoreMarkingDefinition>;
  api_token: string;
}

interface AuthContext {
  otp_mandatory: boolean
  source: string
  tracing: TracingContext
  user: AuthUser | undefined
}
