// Default timeout
jest.setTimeout(700000);
jest.mock("../src/database/migration", () => ({
    applyMigration: () => Promise.resolve(),
    lastAvailableMigrationTime: () => new Date().getTime()
}));
