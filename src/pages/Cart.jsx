import React, { useContext } from "react";
import { CartContext } from "../CartContext.jsx";

const Cart = () => {
  const { cart } = useContext(CartContext);

  return (
    <div style={{ padding: "24px" }}>
      <h2>Shopping Cart</h2>
      {cart.length === 0 ? (
        <p>Your cart is empty.</p>
      ) : (
        <div style={{ display: "flex", gap: "24px", flexWrap: "wrap" }}>
          {cart.map((book) => (
            <div
              key={book.id}
              style={{
                border: "1px solid #eee",
                borderRadius: "8px",
                width: "200px",
                padding: "16px",
                background: "#fff",
                boxShadow: "0 2px 8px rgba(0,0,0,0.05)"
              }}
            >
              <img
                src={book.cover}
                alt={book.title}
                style={{ width: "100%", height: "auto", borderRadius: "4px" }}
              />
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
          ))}
        </div>
      )}
    </div>
  );
};

export default Cart;
