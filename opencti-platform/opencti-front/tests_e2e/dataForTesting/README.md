# E2E initialize data

## STIX data

If you want to add STIX knowledge, simply fill the file _DATA-TEST-STIX2_v2.json_.

The data will be inserted in the platform with the script `yarn insert:dev:e2e`.

## Non STIX data

In this case we cannot use the script, we need to do it manually.

### If there is already some data of the type you want to add

Then simply add yours in the array of the matching data type in `init.data.ts`.

### If no data of the type you want yet

Create a file `[type].data.ts` and take `user.data.ts` as an example.

Then call the new function you created inside the setup file `init.data.ts` with the data you want to add.

## Workflow setup authentication

The workflow setup authenticates its API request context independently before changing
organization access grants. Browser login does not update that context's cookie jar.
After logging in as the workflow manager, setup polls the current user's effective
capabilities and reloads the shell before navigating to Settings. A successful permission
mutation alone is not evidence that the authenticated user has those permissions.

Admin browser storage state is restored in `afterEach`, including failed or timed-out
attempts. Do not move this cleanup to the success-only end of the scenario.

`setupHelpers.spec.ts` covers authentication, permission readiness, and GraphQL failures
against a local fixture HTTP server; it does not mutate platform data.