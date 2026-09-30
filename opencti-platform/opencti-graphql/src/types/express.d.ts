declare namespace Express {
  export interface Request {
    session?: {
      id?: string;
      nonce?: string;
      referer?: string;
      session_provider?: string;
      user?: { id?: string; session_creation?: string; otp_validated?: boolean; password_valid_until?: Date | string | null };
      save: (callback?: (err: unknown) => void) => void;
    };
  }
}
