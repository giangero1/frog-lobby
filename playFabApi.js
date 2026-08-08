export function createPlayFabApi({ apiBase, secretKey, fetchImpl = globalThis.fetch } = {}) {
  const base = String(apiBase ?? "").trim().replace(/\/$/, "");
  const secret = String(secretKey ?? "").trim();
  if (typeof fetchImpl !== "function")
    throw new Error("A fetch implementation is required");

  async function request(path, body, authHeader, authValue) {
    const response = await fetchImpl(`${base}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        [authHeader]: authValue
      },
      body: JSON.stringify(body ?? {})
    });

    const text = await response.text();
    let parsed = null;
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = { raw: text };
      }
    }

    if (!response.ok || parsed?.code === 400 || parsed?.error) {
      const message = parsed?.errorMessage ?? parsed?.error ?? `PlayFab request failed with HTTP ${response.status}`;
      const error = new Error(message);
      error.status = response.status;
      error.playFab = parsed;
      throw error;
    }

    return parsed?.data ?? parsed ?? {};
  }

  return {
    serverRequest(path, body) {
      return request(path, body, "X-SecretKey", secret);
    },

    clientRequest(path, body, sessionTicket) {
      const ticket = String(sessionTicket ?? "").trim();
      if (!ticket) {
        const error = new Error("sessionTicket is required");
        error.status = 401;
        throw error;
      }
      return request(path, body, "X-Authorization", ticket);
    }
  };
}
