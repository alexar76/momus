import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// MOMUS frontend — the adversarial-audit satellite landing + live panel.
// Dev server on 5186 (gaia uses 5181); compose maps 127.0.0.1:5186:80 in prod.
export default defineConfig({
  plugins: [react()],
  server: { port: 5186 },
});
