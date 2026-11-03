import { describe, expect, it, vi } from 'vitest';

vi.mock('nodemailer', async () => {
  const actual = await vi.importActual<typeof import('nodemailer')>('nodemailer');
  return { default: { ...actual, createTransport: vi.fn(actual.createTransport) } };
});

import nodemailer from 'nodemailer';
import '../../../src/database/smtp';

describe('SMTP transporter', () => {
  it('should keep the SMTP transport when the transport selectors are set on the object prototype', async () => {
    const callOptions = (vi.mocked(nodemailer.createTransport).mock.calls[0] as any[])[0];
    const actualNodemailer = await vi.importActual<typeof import('nodemailer')>('nodemailer');
    const prototype = Object.prototype as Record<string, unknown>;
    prototype.sendmail = true;
    prototype.path = '/bin/sh';
    try {
      const transporter = actualNodemailer.createTransport(callOptions);
      expect(transporter.transporter.name).toBe('SMTP');
      transporter.close();
    } finally {
      delete prototype.sendmail;
      delete prototype.path;
    }
  });
});
