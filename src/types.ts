export type User = {
  id: number;
  public_key: string;
  private_key_hash: string;
  iota_id: number;
  token: string;
  username: string;
  display?: string;
  avatar?: Uint8Array | null;
  about?: string;
  status?: string;
  sub_level: number;
  sub_end: number;
};

export type JsonRecord = Record<string, unknown>;
