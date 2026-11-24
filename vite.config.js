import { defineConfig } from "vite";
import probeHandler from "./api/probe.js";

function localProbeApiPlugin() {
  return {
    name: "local-probe-api",
    configureServer(server) {
      server.middlewares.use("/api/probe", async (req, res) => {
        const parsedUrl = new URL(req.url, "http://localhost");
        const query = Object.fromEntries(parsedUrl.searchParams.entries());
        const apiReq = { method: req.method, query };
        const apiRes = {
          setHeader: (k, v) => res.setHeader(k, v),
          status: (code) => {
            res.statusCode = code;
            return {
              json: (payload) => {
                res.setHeader("Content-Type", "application/json");
                res.end(JSON.stringify(payload));
              },
              end: () => res.end()
            };
          }
        };
        try {
          await probeHandler(apiReq, apiRes);
        } catch (err) {
          res.statusCode = 500;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ error: err.message }));
        }
      });
    }
  };
}

export default defineConfig({
  base: "./",
  plugins: [localProbeApiPlugin()],
  build: {
    outDir: "dist"
  }
});
