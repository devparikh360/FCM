import { useState, useEffect } from "react";
import './index.css'; 
import './App.css';

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);

  // user state (null = logged out)
  const [user, setUser] = useState(null);
  // user's history (loaded from localStorage when user logs in)
  const [history, setHistory] = useState([]);

  useEffect(() => {
    const nav = document.querySelector("nav");
    const handleScroll = () => {
      if (window.scrollY > 20) nav.classList.add("scrolled");
      else nav.classList.remove("scrolled");
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  // load history when user changes
  useEffect(() => {
    if (user) {
      const key = `fcm_history_${user.name}`;
      const data = JSON.parse(localStorage.getItem(key)) || [];
      setHistory(data);
    } else {
      setHistory([]);
    }
  }, [user]);

  // fake login (prompt for username). Replace with real auth later.
  const login = () => {
    const name = prompt("Enter username to login", "dev");
    if (!name) return;
    setUser({ name });
    // load history immediately (handled by effect)
  };

  const logout = () => {
    setUser(null);
    // result stays visible if you want; dashboard will hide
  };

  // save an entry for the current user to localStorage
  const saveToHistory = (entry) => {
    if (!user) return;
    const key = `fcm_history_${user.name}`;
    const prev = JSON.parse(localStorage.getItem(key)) || [];
    prev.unshift(entry); // newest first
    localStorage.setItem(key, JSON.stringify(prev));
    setHistory(prev);
  };

  const checkUrl = () => {
    if (!url) return alert("Please enter a URL!");
    const riskScore = Math.floor(Math.random() * 100) + 1;
    const status = riskScore > 70 ? "High Risk" : riskScore > 40 ? "Medium Risk" : "Safe";
    const entry = {
      url,
      score: riskScore,
      status,
      createdAt: new Date().toISOString()
    };
    setResult(entry);
    // only save history if user is logged in
    saveToHistory(entry);
  };

  // scroll to top / hero section (Home)
  const scrollToTop = (e) => {
    e?.preventDefault();
    const el = document.getElementById("home");
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
    else window.scrollTo({ top: 0, behavior: "smooth" });
  };

  // go to dashboard: only available when logged in
  const goToDashboard = (e) => {
    e?.preventDefault();
    if (!user) {
      alert("Please login to view your dashboard.");
      return;
    }
    const el = document.getElementById("dashboard");
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  // remove a history item
  const removeHistoryItem = (idx) => {
    if (!user) return;
    const key = `fcm_history_${user.name}`;
    const copy = [...history];
    copy.splice(idx, 1);
    localStorage.setItem(key, JSON.stringify(copy));
    setHistory(copy);
  };

  return (
    <div className="min-h-screen flex flex-col bg-gray-50 font-sans">
      {/* Navbar */}
      <nav className="bg-gray-900 text-white px-6 py-4 flex justify-between items-center shadow-lg">
        <h1 className="text-2xl font-bold tracking-wide">FakeCatcherMan</h1>

        <div className="nav-actions" style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          {/* Home (explicit handler) */}
          <button className="nav-btn" onClick={scrollToTop}>Home</button>

          {/* Dashboard: only show when logged in */}
          {user && (
            <button className="nav-btn" onClick={goToDashboard}>Dashboard</button>
          )}

          {/* Login / Logout */}
          {!user ? (
            <button className="nav-btn primary" onClick={login}>Login</button>
          ) : (
            <button className="nav-btn danger" onClick={logout}>Logout</button>
          )}
        </div>
      </nav>

      {/* Hero Section */}
      <header id="home" className="flex flex-col items-center justify-center text-center py-20 px-6 bg-gradient-to-r from-indigo-100 to-indigo-50">
        <h2 className="text-4xl font-extrabold mb-4 text-gray-900">Detect Fraudulent Websites Instantly</h2>
        <p className="text-gray-700 mb-8 max-w-3xl text-lg">
          Enter a website URL and let our system detect fraud, phishing attempts, or suspicious activity in real-time.
        </p>

        {/* Input Card */}
        <div className="input-card" style={{ marginTop: 8 }}>
          <input
            type="text"
            placeholder="Enter website URL"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <button onClick={checkUrl}>Check URL</button>
        </div>
      </header>

      {/* Result Cards (appear when a check has been performed) */}
      {result && (
        <section className="result-section" style={{ paddingTop: 28 }}>
          <div className="result-card">
            <h3>Website</h3>
            <p style={{ wordBreak: 'break-all' }}>{result.url}</p>
          </div>
          <div className="result-card">
            <h3>Risk Score</h3>
            <p>{result.score}</p>
          </div>
          <div className={`result-card ${
              result.status === "High Risk" ? "high-risk" :
              result.status === "Medium Risk" ? "medium-risk" :
              "safe"
            }`}>
            <h3>Status</h3>
            <p>{result.status}</p>
          </div>
        </section>
      )}

      {/* Dashboard (always present) */}
      <section id="dashboard" style={{ padding: '2rem 1.5rem' }}>
        <div className="max-width" style={{ maxWidth: 920, margin: '0 auto' }}>
          <h3 style={{ fontSize: '1.25rem', marginBottom: '0.75rem' }}>Dashboard</h3>

          {!user ? (
            <div style={{ padding: '1rem', borderRadius: 12, background: '#fff', boxShadow: '0 6px 18px rgba(0,0,0,0.06)' }}>
              <p style={{ margin: 0 }}>You are not logged in. Click <strong>Login</strong> in the navbar to see your saved URL checks here.</p>
            </div>
          ) : (
            <div>
              <div style={{ marginBottom: 12 }}>
                <strong>Logged in as:</strong> {user.name}
              </div>

              {history.length === 0 ? (
                <div style={{ padding: '1rem', borderRadius: 12, background: '#fff', boxShadow: '0 6px 18px rgba(0,0,0,0.06)' }}>
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
