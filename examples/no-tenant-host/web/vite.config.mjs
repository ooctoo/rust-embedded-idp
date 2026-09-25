import { fileURLToPath } from "node:url";

export default {
  root: fileURLToPath(new URL(".", import.meta.url)),
  base: "/",
  esbuild: { jsx: "automatic" },
  resolve: {
    alias: {
      react: fileURLToPath(new URL("../../../web/node_modules/react", import.meta.url)),
      "react-dom": fileURLToPath(new URL("../../../web/node_modules/react-dom", import.meta.url)),
    },
  },
  build: { outDir: "../dist", emptyOutDir: true },
};
