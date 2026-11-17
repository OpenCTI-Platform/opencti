import { describe, expect, it } from 'vitest';
import { toSingleLineHistoryMessage } from './historyMessage';

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
