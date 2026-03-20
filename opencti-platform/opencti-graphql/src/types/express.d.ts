declare namespace Express {
  export interface Request {
    session?: {
      nonce?: string;
      referer?: string;
    };
  }
}
