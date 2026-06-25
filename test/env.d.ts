import type { SecretStore } from "../src/secret-store";

// cloudflare:test の env に Worker のバインディング型を与える。
declare module "cloudflare:test" {
  interface ProvidedEnv {
    SECRET_STORE: DurableObjectNamespace<SecretStore>;
  }
}
