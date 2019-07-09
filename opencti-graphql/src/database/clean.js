import { write } from './grakn';

const clean = async () => {
  // Delete all users
  await write(`match $x isa User; delete $x;`);
  // Delete all tokens
  await write(`match $x isa Token; delete $x;`);
  // Delete all migrations
  await write(`match $x isa MigrationStatus; delete $x;`);
  await write(`match $x isa MigrationReference; delete $x;`);
};

// noinspection JSIgnoredPromiseFromCall
clean();
