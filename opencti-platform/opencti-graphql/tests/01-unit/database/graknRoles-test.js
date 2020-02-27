import { isInversed } from '../../../src/database/graknRoles';

test('default roles inversion', () => {
  let inverse = isInversed('migrate', 'status');
  expect(inverse).not.toBeTruthy();
  inverse = isInversed('belongs', 'belonging_to');
  expect(inverse).not.toBeTruthy();
  inverse = isInversed('corresponds', 'correspond_to');
  expect(inverse).toBeTruthy();
  inverse = isInversed('unknown', 'from');
  expect(inverse).not.toBeTruthy();
  inverse = isInversed('unknown');
  expect(inverse).not.toBeTruthy();
  inverse = isInversed();
  expect(inverse).not.toBeTruthy();
});
