import { describe, it } from 'vitest';

describe('Observables with hashes: management of other stix ids', () => {
  it('should replace standard_id and add old one in other_stix_ids if prior data arrives', () => {
    // Scenario 1 (upsert)
    // -------------------
    // Create StixFile1 with only name (standard_id based on name) (other_stix_ids empty).
    // UPSERT StixFile1 with name and SHA1 (standard_id based on SHA1) (other_stix_ids has standard_name).
    // UPSERT StixFile1 with name, SHA1 and MD5 (standard_id based on MD5) (other_stix_ids has standard_name, standard_SHA1).

    // Scenario 2 (update)
    // -------------------
    // Create StixFile2 with only name (standard_id based on name) (other_stix_ids empty).
    // UPDATE StixFile2 with name and SHA1 (standard_id based on SHA1) (other_stix_ids has standard_name).
    // UPDATE StixFile2 with name, SHA1 and MD5 (standard_id based on MD5) (other_stix_ids has standard_name, standard_SHA1).
  });

  it('should not replace standard_id if less prior data arrives but still add its standard_id in other_stix_ids', () => {
    // Scenario 1 (upsert)
    // -------------------
    // Create StixFile3 with only MD5 (standard_id based on MD5) (other_stix_ids empty).
    // UPSERT StixFile3 with MD5 and SHA1 (standard_id based on MD5) (other_stix_ids has standard_SHA1).
    // UPSERT StixFile3 with MD5, SHA1 and name (standard_id based on MD5) (other_stix_ids has standard_SHA1, standard_name).

    // Scenario 2 (update)
    // -------------------
    // Create StixFile4 with only MD5 (standard_id based on MD5) (other_stix_ids empty).
    // UPDATE StixFile4 with MD5 and SHA1 (standard_id based on MD5) (other_stix_ids has standard_SHA1).
    // UPDATE StixFile4 with MD5, SHA1 and name (standard_id based on MD5) (other_stix_ids has standard_SHA1, standard_name).
  });

  it('should merge observables and other_stix_ids', () => {
    // Create StixFile5 with only name (standard_id based on name) (other_stix_ids empty).
    // Create StixFile6 with MD5 (standard_id based on MD5) (other_stix_ids empty).
    // Create StixFile7 with MD5 and name => Merge (standard_id based on MD5) (other_stix_ids has standard_name).
  });

  it('should clean standard from other_stix_ids if correlated data is removed', () => {
    // Scenario 1 (no change of standard_id)
    // -------------------------------------
    // UPDATE StixFile4 to remove name (standard_id based on MD5) (other_stix_ids has standard_SHA1).
    // UPDATE StixFile4 to remove SHA1 (standard_id based on MD5) (other_stix_ids empty).

    // Scenario 2 (standard_id changes)
    // --------------------------------
    // UPDATE StixFile3 to remove name (standard_id based on MD5) (other_stix_ids has standard_SHA1).
    // UPDATE StixFile3 to remove MD5 (standard_id based on SHA1) (other_stix_ids empty).
    // UPDATE StixFile2 to remove MD5 (standard_id based on SHA1) (other_stix_ids has standard_name).
    // UPDATE StixFile2 to remove SHA1 (standard_id based on name) (other_stix_ids empty).
  });
});
