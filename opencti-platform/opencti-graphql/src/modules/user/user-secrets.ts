// User attributes holding password hashes: never broadcast, never carried by a context user.
export const USER_SECRET_ATTRIBUTES = ['password', 'password_history'];

export const withoutUserSecrets = <T extends Record<string, any>>(user: T): T => {
  return Object.fromEntries(Object.entries(user).filter(([key]) => !USER_SECRET_ATTRIBUTES.includes(key))) as T;
};
