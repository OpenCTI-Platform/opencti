declare namespace Express {
  export interface Request {
    session?: {
      nonce?: string;
      referer?: string;
      regenerate: (callback: (err: unknown) => void) => void;
    };
  }
}
