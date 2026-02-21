import { useState, useEffect, useCallback } from "react";
import { CartProvider } from "./CartContext.jsx";
import { BrowserRouter, Routes, Route, Link } from "react-router-dom";
import Home from "./pages/Home.jsx";
import BookList from "./pages/BookList.jsx";
import Cart from "./pages/Cart.jsx";
import Checkout from "./pages/Checkout.jsx";
import Profile from "./pages/Profile.jsx";
import Register from "./pages/Register.jsx";
import Login from "./pages/Login.jsx";
import Logout from "./pages/Logout.jsx";
function App() {
  const getUsernameFromToken = useCallback(() => {
    const token = localStorage.getItem("token");
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split(".")[1]));
        return payload.username;
      } catch {
        return null;
      }
    }
    return null;
  }, []);
  const [user, setUser] = useState(getUsernameFromToken());
  const [cartCount, setCartCount] = useState(0);

  useEffect(() => {
    const handleStorage = () => {
      setUser(getUsernameFromToken());
      // Update cart count
      const storedCart = localStorage.getItem("cart");
      if (storedCart) {
        const cartArr = JSON.parse(storedCart);
        const count = cartArr.reduce((sum, item) => sum + (item.quantity || 1), 0);
        setCartCount(count);
      } else {
        setCartCount(0);
      }
    };
    window.addEventListener("storage", handleStorage);
    // Also check on mount
    handleStorage();
    // Listen for route changes
    const observer = new MutationObserver(() => {
      setUser(getUsernameFromToken());
      handleStorage();
    });
    observer.observe(document.body, { childList: true, subtree: true });
    return () => {
      window.removeEventListener("storage", handleStorage);
      observer.disconnect();
    };
  }, [getUsernameFromToken]);

  return (
    <CartProvider>
      <BrowserRouter>
        <div>
          <header
            style={{
              background: "linear-gradient(90deg, #1677FF 0%, #52C41A 100%)",
              color: "white",
              padding: "16px 32px",
              boxShadow: "0 2px 8px rgba(0,0,0,0.05)",
              position: "fixed",
              top: 0,
              left: 0,
              width: "100%",
              zIndex: 1000,
            }}
          >
            <span
              style={{
                fontSize: "2.5rem",
                fontWeight: "bold",
                letterSpacing: "2px",
                color: "#fff",
                textShadow: "0 2px 8px rgba(0,0,0,0.15)",
                marginRight: "32px",
              }}
            >
              ShelfX
            </span>
            <nav style={{ fontSize: "1.1rem" }}>
              <Link
                to="/"
                style={{
                  color: "white",
                  marginRight: "16px",
                  textDecoration: "none",
                  fontWeight: "bold",
                }}
              >
                Home
              </Link>
              <Link
                to="/books"
                style={{
                  color: "white",
                  marginRight: "16px",
                  textDecoration: "none",
                  fontWeight: "bold",
                }}
              >
                Books
              </Link>
              <Link
                to="/cart"
                style={{
                  color: "white",
                  marginRight: "16px",
                  textDecoration: "none",
                  fontWeight: "bold"
                }}
              >
                Cart
              </Link>
              <Link
                to="/checkout"
                style={{
                  color: "white",
                  marginRight: "16px",
                  textDecoration: "none",
                  fontWeight: "bold",
                }}
              >
                Checkout
              </Link>
              <Link
                to="/profile"
                style={{
                  color: "white",
                  marginRight: "16px",
                  textDecoration: "none",
                  fontWeight: "bold",
                }}
              >
                Profile
              </Link>
              {!user ? (
                <>
                  <Link
                    to="/register"
                    style={{
                      color: "white",
                      marginRight: "16px",
                      textDecoration: "none",
                      fontWeight: "bold",
                    }}
                  >
                    Register
                  </Link>
                  <Link
                    to="/login"
                    style={{
                      color: "white",
                      marginRight: "16px",
                      textDecoration: "none",
                      fontWeight: "bold",
                    }}
                  >
                    Login
                  </Link>
                </>
              ) : (
                <div style={{ display: "inline-block", position: "relative" }}>
                  <button
                    type="button"
                    style={{
                      background: "none",
                      border: "none",
                      color: "white",
                      fontWeight: "bold",
                      marginRight: "16px",
                      cursor: "pointer",
                      fontSize: "1.1rem",
                    }}
                    onClick={() => {
                      const menu = document.getElementById("user-menu");
                      if (menu)
                        menu.style.display =
                          menu.style.display === "block" ? "none" : "block";
                    }}
                  >
                    {user}
                  </button>
                  <div
                    id="user-menu"
                    style={{
                      display: "none",
                      position: "absolute",
                      right: 0,
                      top: "100%",
                      background: "white",
                      color: "#1677FF",
                      borderRadius: "4px",
                      boxShadow: "0 2px 8px rgba(0,0,0,0.15)",
                      minWidth: "120px",
                      zIndex: 1001,
                    }}
                  >
                    <Link
                      to="/logout"
                      style={{
                        display: "block",
                        padding: "8px 16px",
                        color: "#1677FF",
                        textDecoration: "none",
                        fontWeight: "bold",
                      }}
                      onClick={() => {
                        document.getElementById("user-menu").style.display =
                          "none";
                      }}
                    >
                      Logout
                    </Link>
                  </div>
                </div>
              )}
            </nav>
          </header>
          <div style={{ marginTop: "120px", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", minHeight: "70vh" }}>
            <main style={{ width: "100%", maxWidth: "900px" }}>
              <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/books" element={<BookList />} />
                <Route path="/cart" element={<Cart />} />
                <Route path="/checkout" element={<Checkout />} />
                <Route path="/profile" element={<Profile />} />
                <Route path="/register" element={<Register />} />
                <Route path="/login" element={<Login />} />
                <Route path="/logout" element={<Logout />} />
              </Routes>
            </main>
          </div>
        </div>
      </BrowserRouter>
    </CartProvider>
  );
}

export default App;
