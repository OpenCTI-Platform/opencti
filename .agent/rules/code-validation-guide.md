---
trigger: always_on
---

**Strict Coverage Rule:**
You must achieve **100% code coverage** for all NEW implementation (lines and branches) using coverage tools (`vitest --coverage`)
If covereage is not 100%, you MUST write unit tests and integration tests to cover the missing lines and branches.

**Post-Edit Requirement:** 
When considering a work done for opencti-graphql, you MUST:
*   Check typescript integrity `yarn check-ts`
*   Checking linting rules, `yarn lint`
*   Checking building succeed, `yarn build`
*   Run and check relevant unit tests (`npx vitest run ...`)
*   Run and check relevant integration Tests (`npx vitest run ... --config vitest.config.integration.ts`)

When considering a work done for opencti-front, you MUST:
*   Check typescript integrity `yarn check-ts`
*   Checking linting rules, `yarn lint`
*   Checking relay build succeed, `yarn relay`

**Naming:**
*   Files: `camelCase.js` (Backend), `PascalCase.tsx` (Frontend Components).
*   GraphQL: `snake_case` for fields, `PascalCase` for Types.