import React, { useContext, useState } from "react";
import { CartContext } from "../CartContext.jsx";
import { useNavigate } from "react-router-dom";

const Cart = () => {
  const { cart } = useContext(CartContext);
  const [selected, setSelected] = useState([]);
  const navigate = useNavigate();

  // Handle selection toggle
  const handleSelect = (id) => {
    setSelected((prev) =>
      prev.includes(id)
        ? prev.filter((bookId) => bookId !== id)
        : [...prev, id]
    );
  };

  // Select all
  const handleSelectAll = () => {
    if (selected.length === cart.length) {
      setSelected([]);
    } else {
      setSelected(cart.map((book) => book.id));
    }
  };

  // Calculate total price for selected books
  const totalPrice = cart
    .filter((book) => selected.includes(book.id))
    .reduce((sum, book) => sum + (book.price * (book.quantity || 1)), 0);

  return (
    <div style={{ padding: "24px" }}>
      <h2>Shopping Cart</h2>
      {cart.length === 0 ? (
        <p>Your cart is empty.</p>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "24px", flexWrap: "nowrap", position: "relative" }}>
          <div style={{ width: "100%", marginBottom: "16px" }}>
            <label style={{ fontWeight: "bold", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={selected.length === cart.length && cart.length > 0}
                onChange={handleSelectAll}
                style={{ marginRight: "8px" }}
              />
              Select All
            </label>
          </div>
          {cart.map((book) => (
            <div
              key={book.id}
              style={{
                border: "1px solid #eee",
                borderRadius: "8px",
                width: "100%",
                padding: "16px",
                background: "#fff",
                boxShadow: "0 2px 8px rgba(0,0,0,0.05)",
                position: "relative",
                display: "flex",
                alignItems: "center",
                gap: "16px"
              }}
            >
              <input
                type="checkbox"
                checked={selected.includes(book.id)}
                onChange={() => handleSelect(book.id)}
                style={{ marginRight: "16px", transform: "scale(1.2)" }}
              />
              <img
                src={book.cover}
                alt={book.title}
                style={{ width: "80px", height: "auto", borderRadius: "4px" }}
              />
              <div style={{ flex: 1 }}>
                <div style={{ display: "flex", alignItems: "center", margin: "12px 0 4px 0" }}>
                  <h3 style={{ margin: 0 }}>{book.title}</h3>
                  <span style={{
                    marginLeft: "8px",
                    background: "#52C41A",
                    color: "white",
                    borderRadius: "12px",
                    padding: "2px 10px",
                    fontSize: "1rem",
                    fontWeight: "bold"
                  }}>
                    x{book.quantity || 1}
                  </span>
                </div>
                <p style={{ margin: "0", color: "#888" }}>by {book.author}</p>
                <p style={{ margin: "8px 0", fontWeight: "bold" }}>
                  ${book.price.toFixed(2)}
                </p>
                <p style={{ margin: "0", color: "#52C41A" }}>{book.category}</p>
              </div>
            </div>
          ))}
          {selected.length > 0 && (
            <div style={{
              position: "fixed",
              right: "32px",
              bottom: "32px",
              fontSize: "1.3rem",
              fontWeight: "bold",
              color: "#1677FF",
              background: "#fff",
              borderRadius: "8px",
              boxShadow: "0 2px 8px rgba(0,0,0,0.10)",
              padding: "16px 24px",
              zIndex: 1002,
              display: "flex",
              alignItems: "center",
              gap: "16px"
            }}>
              <span>Total Price: ${totalPrice.toFixed(2)}</span>
              <button
                style={{
                  padding: "8px 20px",
                  background: "#1677FF",
                  color: "white",
                  border: "none",
                  borderRadius: "6px",
                  fontWeight: "bold",
                  fontSize: "1rem",
                  cursor: "pointer",
                  boxShadow: "0 2px 6px rgba(0,0,0,0.1)"
                }}
                onClick={() => {
                  localStorage.setItem("selectedCartIds", JSON.stringify(selected));
                  navigate("/checkout");
                }}
              >
                Go to Checkout
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Cart;
