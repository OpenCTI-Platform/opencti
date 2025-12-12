import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

describe('File resolver standard behavior', () => {
  // TODO: this test suite should address all queries and mutations from src/resolvers/file.js

  it('should guess mimetypes correctly', async () => {
    const GUESS_MIMETYPE_QUERY = gql`
      query guessMimeType {
        file1: guessMimeType(fileId: "pdf_report")
        file2: guessMimeType(fileId: "path/1/file.yar")
        file3: guessMimeType(fileId: "path/to/iamajsonfile.json")
        file4: guessMimeType(fileId: "path/to/iamapdf.pdf")
        file5: guessMimeType(fileId: "path/to/i Have space and 💖.txt")
        file6: guessMimeType(fileId: "unknown")
        file7: guessMimeType(fileId: "export/Malware/b4bebef0-7f1b-4212-b09d-f376adb3181a/(ExportFileStix)_Malware-Paradise Ransomware_all.json")
      }
    `;
    const queryResult = await queryAsAdmin({
      query: GUESS_MIMETYPE_QUERY,
    });

    expect(queryResult.data?.file1).toBe('application/pdf');
    expect(queryResult.data?.file2).toBe('text/yara+plain');
    expect(queryResult.data?.file3).toBe('application/json');
    expect(queryResult.data?.file4).toBe('application/pdf');
    expect(queryResult.data?.file5).toBe('text/plain');
    expect(queryResult.data?.file6).toBe('application/octet-stream');
    expect(queryResult.data?.file7).toBe('application/json');
  });
});
