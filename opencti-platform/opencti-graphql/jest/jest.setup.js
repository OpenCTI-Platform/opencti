import cacheManager from "../src/manager/cacheManager";
import { initializeSession } from "../src/database/session";

// Mock the migrations
jest.mock("../src/database/migration", () => ({
    applyMigration: () => Promise.resolve(),
    lastAvailableMigrationTime: () => new Date().getTime()
}));

// Setup and close cache Manager for each test
global.beforeAll(async () => {
    initializeSession();
    // Default timeout
    jest.setTimeout(1200000);
    await cacheManager.start();
});
global.afterAll(async () => {
    await cacheManager.shutdown();
});
