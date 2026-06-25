import { DurableObject } from "cloudflare:workers";

// KV に保存するレコード。鍵・平文は構造上含まれない。
export type SecretRecord = {
  ct: string; // base64url(暗号文 + 認証タグ)
  iv: string; // base64url(12 バイト)
  salt: string | null; // base64url(16 バイト)。パスフレーズなしなら null
  maxViews: number;
  views: number;
  expiresAt: number; // 絶対エポック秒
};

// クライアントへ返すレコード。鍵は含まない。
export type PublicRecord = {
  ct: string;
  iv: string;
  salt: string | null;
  maxViews: number;
  views: number;
};

// 1 つの秘密につき 1 インスタンス。単一スレッドで read→burn を直列化し、
// KV の結果整合では得られない exactly-once を保証する。
export class SecretStore extends DurableObject {
  // 暗号文を保存し、期限到達時の自動削除アラームを設定する。
  async create(record: SecretRecord): Promise<void> {
    await this.ctx.storage.put("record", record);
    await this.ctx.storage.setAlarm(record.expiresAt * 1000);
  }

  // 暗号文を 1 回分取得する。開封上限に達した時点で破棄する。
  // 不在・期限切れは null（呼び出し側で gone として扱う）。
  async read(): Promise<PublicRecord | null> {
    const record = await this.ctx.storage.get<SecretRecord>("record");
    if (!record) return null;

    const now = Math.floor(Date.now() / 1000);
    if (now >= record.expiresAt) {
      await this.ctx.storage.deleteAll();
      return null;
    }

    record.views += 1;
    if (record.views >= record.maxViews) {
      await this.ctx.storage.deleteAll();
    } else {
      await this.ctx.storage.put("record", record);
    }

    return {
      ct: record.ct,
      iv: record.iv,
      salt: record.salt,
      maxViews: record.maxViews,
      views: record.views,
    };
  }

  // 期限到達時に呼ばれ、未開封のまま残った暗号文を破棄する。
  async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}
