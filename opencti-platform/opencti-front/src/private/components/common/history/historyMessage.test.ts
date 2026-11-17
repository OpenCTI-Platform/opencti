import { describe, expect, it } from 'vitest';
import { toPlainHistoryValue, toSingleLineHistoryMessage } from './historyMessage';

describe('toSingleLineHistoryMessage', () => {
  it('should return an empty string for no message', () => {
    expect(toSingleLineHistoryMessage(null)).toEqual('');
    expect(toSingleLineHistoryMessage(undefined)).toEqual('');
  });
  it('should keep a clean message as it is', () => {
    expect(toSingleLineHistoryMessage('replaces `ANALYZED` in `Workflow status`'))
      .toEqual('replaces `ANALYZED` in `Workflow status`');
  });
  it('should remove html tags and line breaks stored in an old message', () => {
    const stored = 'replaces `<h1>CERT-FR Advisory</h1>\n<p>Subject: Multiple vul...` in `Content` | adds `vulnerability-advisory` in `Report types`';
    expect(toSingleLineHistoryMessage(stored))
      .toEqual('replaces ` CERT-FR Advisory Subject: Multiple vul...` in `Content` | adds `vulnerability-advisory` in `Report types`');
  });
  it('should decode html entities and drop script content', () => {
    expect(toSingleLineHistoryMessage('replaces `a &amp; b<script>alert(1)</script>` in `Content`'))
      .toEqual('replaces `a & b ` in `Content`');
  });
});

describe('toPlainHistoryValue', () => {
  it('should return an empty string for no value', () => {
    expect(toPlainHistoryValue(null)).toEqual('');
  });
  it('should show html content as readable text, never cut', () => {
    const content = '<h1>CERT-FR Advisory</h1>\n<p>Subject: A &amp; B <strong>critical</strong></p><ul><li>CVE-2026-0001</li></ul><script>alert(1)</script>';
    expect(toPlainHistoryValue(content)).toEqual('CERT-FR Advisory Subject: A & B critical CVE-2026-0001');
  });
  it('should remove markdown marks and keep the case of the data', () => {
    const description = '# Title\nA **long** `CVE-2026-0002` [link](https://example.com)\n- item';
    expect(toPlainHistoryValue(description)).toEqual('Title A long CVE-2026-0002 link item');
  });
});
