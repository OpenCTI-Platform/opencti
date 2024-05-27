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