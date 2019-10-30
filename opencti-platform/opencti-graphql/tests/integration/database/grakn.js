import { graknIsAlive } from '../../../src/database/grakn';

describe('Database init', () => {
  it('should database accessible', () => {
    expect(graknIsAlive()).toBeTruthy();
  });
});
