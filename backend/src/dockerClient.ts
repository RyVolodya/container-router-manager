import http from "node:http";

const socketPath = process.env.DOCKER_SOCKET ?? "/var/run/docker.sock";

export async function dockerRequest<T>(
  path: string,
  method: "GET" | "POST" | "DELETE" = "GET",
  body?: unknown
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const headers: Record<string,string|number> = { Host: "localhost" };
    if (payload !== undefined) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(payload);
    }

    const req = http.request(
      { socketPath, path, method, headers },
      (res) => {
        let responseBody = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => (responseBody += chunk));
        res.on("end", () => {
          const statusCode = res.statusCode ?? 500;
          if (statusCode < 200 || statusCode >= 300) {
            let message = responseBody;
            try {
              const parsed = JSON.parse(responseBody);
              message = parsed.message ?? responseBody;
            } catch {}
            reject(new Error(`Docker API HTTP ${statusCode}: ${message}`));
            return;
          }

          if (!responseBody.trim()) {
            resolve(undefined as T);
            return;
          }

          try {
            resolve(JSON.parse(responseBody) as T);
          } catch (error) {
            reject(new Error(`Invalid Docker API JSON: ${String(error)}`));
          }
        });
      }
    );
    req.on("error", reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

export async function dockerGet<T>(path: string): Promise<T> {
  return dockerRequest<T>(path, "GET");
}

export async function dockerPost<T>(path: string, body?: unknown): Promise<T> {
  return dockerRequest<T>(path, "POST", body);
}

export async function dockerDelete(path: string): Promise<void> {
  await dockerRequest<void>(path, "DELETE");
}
