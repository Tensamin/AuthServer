export type User = {
  uuid: string;
  public_key: string;
  private_key_hash: string;
  iota_id: string;
  token: string;
  username: string;
  created_at: number;
  display?: string;
  avatar?: Uint8Array | null;
  about?: string;
  status?: string;
  sub_level: number;
  sub_end: number;
};

export type JsonRecord = Record<string, unknown>;
