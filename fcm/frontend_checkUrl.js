// frontend_checkUrl.js
// Paste the checkUrl function into your App.js (or import it).
// Notes:
//  - Set REACT_APP_API_URL in your frontend .env (e.g. REACT_APP_API_URL=http://localhost:5000)
//  - The backend (patched_api.py) will already persist results to Firebase; client-side Firestore write is optional.

export async function checkUrl(url, setResult, setHistory) {
  const API = process.env.REACT_APP_API_URL || "http://localhost:5000";
  try {
    const resp = await fetch(`${API}/detect/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Server error ${resp.status}: ${text}`);
    }
    const data = await resp.json();
    console.log("Detection response:", data);

    // Normalized object your UI can use
    const normalized = {
      url: data.url || url,
      score: data?.result?.score ?? data?.score ?? null,
      status: data?.result?.status ?? data?.status ?? null,
      backendRaw: data,
    };

    // set React state (example)
    if (typeof setResult === "function") setResult(normalized);

    // Save to local history in UI (optional)
    try {
      if (typeof setHistory === "function") {
        setHistory((prev) => {
          const next = [normalized].concat(prev || []);
          // limit history size
          return next.slice(0, 50);
        });
      }
    } catch (e) {
      console.warn("Failed to update client-side history:", e);
    }

    return normalized;
  } catch (err) {
    console.error("checkUrl error:", err);
    throw err;
  }
}

/*
.env (place in FCM/fcm/.env.local or similar)
REACT_APP_API_URL=http://localhost:5000
*/
