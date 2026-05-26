import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: ["src/index.ts"],
    format: ["esm"],
    outDir: "dist/esm",
    dts: false,
    outExtension: () => ({ js: ".js" }),
    splitting: false,
    sourcemap: false,
    clean: true,
    target: "node20",
  },
  {
    entry: ["src/index.ts"],
    format: ["cjs"],
    outDir: "dist/cjs",
    dts: false,
    outExtension: () => ({ js: ".cjs" }),
    splitting: false,
    sourcemap: false,
    clean: false,
    target: "node20",
  },
  {
    entry: ["src/index.ts"],
    format: ["esm"],
    outDir: "dist/types",
    dts: { only: true },
    splitting: false,
    sourcemap: false,
    clean: false,
    target: "node20",
  },
]);
