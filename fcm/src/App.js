import { useState, useEffect } from "react";
import "./index.css";
import "./App.css";
import { auth, provider, db } from "./firebase"; // kept as in your original file
import {
  signInWithPopup,
  onAuthStateChanged,
  signOut,
} from "firebase/auth";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);

  // Firebase user
  const [user, setUser] = useState(null);

  // user's history (loaded from localStorage when user logs in)
  const [history, setHistory] = useState([]);

  // listen for auth state changes
  useEffect(() => {
    const unsub = onAuthStateChanged(auth, (currentUser) => {
      setUser(currentUser);
    });
    return () => unsub();
  }, []);

  // load history when user changes
  useEffect(() => {
    if (user) {
      const key = `fcm_history_${user.uid}`;
      const data = JSON.parse(localStorage.getItem(key)) || [];
      setHistory(data);
    } else {
      setHistory([]);
    }
  }, [user]);

  // Login with Google (popup)
  const login = async () => {
    try {
      const res = await signInWithPopup(auth, provider);
      setUser(res.user); // stores logged in user
      console.log("User logged in:", res.user);
    } catch (err) {
      console.error("Login Failed", err.message);
      alert("Login failed. Check console for details.");
    }
  };

  const logout = async () => {
    try {
      await signOut(auth);
      setUser(null);
      console.log("User logged out");
    } catch (error) {
      console.error("Logout failed:", error.message);
    }
  };

  // Save an entry for the current user to localStorage
  const saveToHistory = (entry) => {
    if (!user) return;
    const key = `fcm_history_${user.uid}`;
    const prev = JSON.parse(localStorage.getItem(key)) || [];
    prev.unshift(entry); // newest first
    localStorage.setItem(key, JSON.stringify(prev));
    setHistory(prev);
  };

// Check URL -> call backend API and map response to the same shape your UI expects
// Example: check a URL
async function checkUrl(url) {
  try {
    const response = await fetch("http://127.0.0.1:5000/detect/url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }),
    });

    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }

    const data = await response.json();
    console.log("Raw backend response:", data);

    // normalize backend response into { url, score, status }
    const normalized = {
      url: data.url || url,
      score:
        data?.result?.score ??
        data?.score ??
        data?.score_value ??
        null,
      status:
        data?.result?.status ??
        data?.status ??
        data?.label ??
        data?.verdict ??
        null,
    };

    setResult(normalized);

    // save to history if logged in
    if (user) {
      saveToHistory({ ...normalized, createdAt: new Date().toISOString() });
    }
  } catch (error) {
    console.error("Error during fetch:", error);
    setResult({ url, score: null, status: "Error: " + error.message });
  }
}
/*
function checkUrl(url) {
    // generate random score
    const score = Math.floor(Math.random() * 101); // 0–100
    let status;
    if (score >= 70) {
      status = "High Risk";
    } else if (score >= 40) {
      status = "Medium Risk";
    } else {
      status = "Safe";
    }

    const normalized = { url, score, status };
    setResult(normalized);

    if (user) {
      saveToHistory({ ...normalized, createdAt: new Date().toISOString() });
    }
  }
    */
  
  // Scroll to top / hero section (Home)
  const scrollToTop = (e) => {
    e?.preventDefault();
    const el = document.getElementById("home");
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
    else window.scrollTo({ top: 0, behavior: "smooth" });
  };

  // Go to dashboard: only available when logged in
  const goToDashboard = (e) => {
    e?.preventDefault();
    if (!user) {
      alert("Please login to view your dashboard.");
      return;
    }
    const el = document.getElementById("dashboard");
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  // Remove a history item
  const removeHistoryItem = (idx) => {
    if (!user) return;
    const key = `fcm_history_${user.uid}`;
    const copy = [...history];
    copy.splice(idx, 1);
    localStorage.setItem(key, JSON.stringify(copy));
    setHistory(copy);
  };

  return (
    <div className="min-h-screen flex flex-col bg-gray-50 font-sans">
      {/* Navbar */}
      <nav className="bg-gray-900 text-white px-8 py-4 flex justify-between items-center shadow-lg">
        <h1 className="text-2xl font-bold tracking-wide">FakeCatcherMan</h1>

        <div
          className="nav-actions"
          style={{
            display: "flex",
            gap: "1rem",
            alignItems: "center",
          }}
        >
          <button className="nav-btn" onClick={scrollToTop}>
            Home
          </button>

          {user && (
            <button className="nav-btn" onClick={goToDashboard}>
              Dashboard
            </button>
          )}
          <div>
            {!user ? (
              <button onClick={login}>Login with Google</button>
            ) : (
              <>
                <button onClick={logout}>Logout</button>
              </>
            )}
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <header
        id="home"
        className="flex flex-col items-center justify-center text-center py-20 px-6 bg-gradient-to-r from-indigo-100 to-indigo-50"
      >
        <h2 className="text-4xl font-extrabold mb-4 text-gray-900">
          Detect Fraudulent Websites Instantly
        </h2>
        <p className="text-gray-700 mb-8 max-w-3xl text-lg">
          Enter a website URL and let our system detect fraud, phishing
          attempts, or suspicious activity in real-time.
        </p>

        {/* Input Card */}
        <div className="input-card" style={{ marginTop: 8 }}>
          <input
            type="text"
            placeholder="Enter website URL"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
         <button 
  onClick={() => url.trim() && checkUrl(url)} 
  disabled={!url.trim()}
>
  Check URL
</button>


        </div>
      </header>

      {/* Result Cards */}
      {result && (
        <section className="result-section" style={{ paddingTop: 28 }}>
          <div className="result-card">
            <h3>Website</h3>
            <p style={{ wordBreak: "break-all" }}>{result.url}</p>
          </div>
          <div className="result-card">
            <h3>Risk Score</h3>
            <p>{result.score}</p>
          </div>
          <div
            className={`result-card ${
              result.status === "High Risk"
                ? "high-risk"
                : result.status === "Medium Risk"
                ? "medium-risk"
                : "safe"
            }`}
          >
            <h3>Status</h3>
            <p>{result.status}</p>
          </div>
        </section>
      )}

      {/* Dashboard */}
      <section id="dashboard" style={{ padding: "2rem 1.5rem" }}>
        <div className="max-width" style={{ maxWidth: 920, margin: "0 auto" }}>
          <h3 style={{ fontSize: "1.25rem", marginBottom: "0.75rem" }}>
            Dashboard
          </h3>

          {!user ? (
            <div style={{ padding: "1rem", borderRadius: 12, background: "#fff", boxShadow: '0 6px 18px rgba(0,0,0,0.06)' }}>
              <p style={{ margin: 0 }}>
                You are not logged in. Click <strong>Login</strong> in the navbar to see your saved URL checks here.
              </p>
            </div>
          ) : (
            <div>
              <div style={{ marginBottom: 12 }}>
                <strong>Logged in as:</strong> {user.displayName || user.email}
              </div>

              {history.length === 0 ? (
                <div style={{ padding: '1rem', borderRadius: 12, background: '#fff', boxShadow: '0 6px 18px rgba(0,0,0,0.06)'}}>
                  <p style={{ margin: 0 }}>No URL checks saved yet. When you check a URL while logged in it will be stored here.</p>
                </div>
              ) : (
                <div style={{ display: 'grid', gap: 12 }}>
                  {history.map((h, idx) => (
                    <div key={idx} className="history-item" style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'0.75rem', borderRadius:10, background:'#fff', boxShadow: '0 6px 18px rgba(0,0,0,0.06)'}}>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontWeight: 700 }}>{h.url}</div>
                        <div style={{ fontSize: 13, color: '#6b7280' }}>{h.status} · Score: {h.score} · {new Date(h.createdAt).toLocaleString()}</div>
                      </div>
                      <div style={{ marginLeft: 12 }}>
                        <button className="small-btn" onClick={() => removeHistoryItem(idx)}>Delete</button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-gray-900 text-white text-center py-6 mt-auto">
        <p>© 2025 FakeCatcherMan. All rights reserved.</p>
        <p>Dev Parikh & Dhaval Amin</p>
      </footer>
    </div>
  );
}

export default App;
