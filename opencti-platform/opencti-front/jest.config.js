const config = {
    roots: ["<rootDir>/src"],
    collectCoverageFrom: [
        "src/**/*.{js,jsx,ts,tsx}",
        "!src/**/*.graphql.{js,jsx,ts,tsx}",
        "!src/**/*.d.ts"
    ],
    testMatch: [
        "<rootDir>/src/**/__tests__/**/*.{js,jsx,ts,tsx}",
        "<rootDir>/src/**/*.{spec,test}.{js,jsx,ts,tsx}"
    ],
    testEnvironment: "jsdom",
    transform: {
        "^.+\\.(js|jsx|mjs|cjs|ts|tsx)$": "<rootDir>/jest/jest.relay.transform.js",
        "^(?!.*\\.(js|jsx|mjs|cjs|ts|tsx|css|json)$)": "<rootDir>/jest/jest.file.transform.js"
    },
    transformIgnorePatterns: [
        "^.+\\.module\\.(css|sass|scss)$"
    ]
};

module.exports = config;
