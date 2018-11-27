import { qk } from './grakn';

const clean = async () => {
  // Delete all users
  await qk(`match $x isa User; delete $x;`);
  // Delete all tokens
  await qk(`match $x isa Token; delete $x;`);
  // Delete all migrations
  await qk(`match $x isa MigrationStatus; delete $x;`);
  await qk(`match $x isa MigrationReference; delete $x;`);
};

// noinspection JSIgnoredPromiseFromCall
clean();
