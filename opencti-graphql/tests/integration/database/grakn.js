import { read } from '../../../src/database/grakn';

describe('Database init', () => {
  it('should database accessible', () => {
    read('match $x sub entity; get $x;');
  });
});
