export interface BaseElement {
  internal_id: string;
  object_marking_refs: Array<string> | [];
}

export interface Marking extends BaseElement {
  name: string;
}

export interface Role {
  name: string;
}

export interface Capability {
  name: string;
}

export interface UserOrigin {
  name?: string;
  user_id?: string;
  referer?: string;
}

export interface AuthUser {
  id: string;
  internal_id: string;
  name: string;
  user_email: string;
  origin: Partial<UserOrigin>;
  roles: Array<Role>;
  capabilities: Array<Capability>;
  allowed_marking: Array<Marking>;
}

export interface StatusTemplateInput {
  name: string;
  color: string;
}

export interface StatusInput {
  template_id: string;
  order: number;
}
