import { assertUserRole, ROLE_ADMIN, ROLE_USER } from '../user';

test('Validation of roles assertion', () => {
  const user = { roles: [ROLE_ADMIN] };
  expect(assertUserRole(user, ROLE_ADMIN)).toBeUndefined();
  expect(() => assertUserRole(user, ROLE_USER)).toThrow();
});
