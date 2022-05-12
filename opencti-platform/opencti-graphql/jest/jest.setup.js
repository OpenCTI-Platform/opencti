// Default timeout
import cacheManager from "../src/manager/cacheManager";

jest.setTimeout(700000);
jest.mock("../src/database/migration", () => ({
    applyMigration: () => Promise.resolve(),
    lastAvailableMigrationTime: () => new Date().getTime()
}));
global.beforeAll(async () => {
    await cacheManager.start();
});
global.afterAll(async () => {
    await cacheManager.shutdown();
});
