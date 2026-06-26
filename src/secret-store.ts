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

// 1 つの秘密につき 1 インスタンス。単一スレッドで読み取りと破棄を直列化し、
// KV の結果整合では得られない exactly-once を保証する。
export class SecretStore extends DurableObject {
  // 暗号文を保存し、期限到達時の自動削除アラームを設定する。
  // 既存レコードがあれば上書きせず false を返す（id 衝突時の黙殺破壊を防ぐ）。
  async create(record: SecretRecord): Promise<boolean> {
    if (await this.ctx.storage.get("record")) return false;
    await this.ctx.storage.put("record", record);
    await this.ctx.storage.setAlarm(record.expiresAt * 1000);
    return true;
  }

  // 暗号文を 1 回分取得する。開封上限に達した時点で破棄する。
  // 不在・期限切れは null（呼び出し側で gone として扱う）。
  async read(): Promise<PublicRecord | null> {
    const record = await this.ctx.storage.get<SecretRecord>("record");
    if (!record) return null;

    const now = Math.floor(Date.now() / 1000);
    if (now >= record.expiresAt) {
      await this.destroy();
      return null;
    }

    record.views += 1;
    if (record.views >= record.maxViews) {
      await this.destroy();
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
  // 例外時はランタイムが自動でアラームを再試行するため、ここでは握り潰さない。
  async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }

  // レコードと、保留中の自動削除アラームをまとめて破棄する。
  // 早期破棄後に不要なアラーム起動（無駄な書き込み）が残らないようにする。
  private async destroy(): Promise<void> {
    await this.ctx.storage.deleteAll();
    // アラーム解除は best-effort。失敗しても消費自体は成立しているので例外にしない
    // （残ったアラームは後で 1 度起動するが、空ストレージを消すだけで無害）。
    try {
      await this.ctx.storage.deleteAlarm();
    } catch (e) {
      console.warn("deleteAlarm failed after destroy:", e);
    }
  }
}
