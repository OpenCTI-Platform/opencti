declare namespace Express {
  export interface Request {
    session?: {
      id?: string;
      nonce?: string;
      referer?: string;
      user?: { id?: string };
    };
  }
}
