export interface AuthUser {
  email: string;
}

export interface StatusTemplateInput {
  name: string;
  color: string;
}

export interface StatusInput {
  template_id: string;
  order: number;
}
