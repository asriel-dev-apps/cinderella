import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

// 実 workerd ランタイム + ローカル KV（miniflare）でテストする。
// wrangler.toml の SECRETS バインディングをそのまま利用する。
export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: "./wrangler.toml" },
      },
    },
  },
});
