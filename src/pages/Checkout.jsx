import React, { useContext, useState } from "react";
import { CartContext } from "../CartContext.jsx";

const Checkout = () => {
  const { cart, setCart } = useContext(CartContext);
  const [showPopup, setShowPopup] = useState(false);
  const [emailReceipt, setEmailReceipt] = useState(null);
  const [showConfirm, setShowConfirm] = useState(false);
  const [emailInput, setEmailInput] = useState("");
  const [cleared, setCleared] = useState(false);

  // Get selected books from localStorage (set in Cart page)
  const selectedIds = JSON.parse(localStorage.getItem("selectedCartIds") || "[]");
  const selectedBooks = cart.filter(book => selectedIds.includes(book.id));
  const totalPrice = selectedBooks.reduce((sum, book) => sum + (book.price * (book.quantity || 1)), 0);

  const handlePay = () => {
    setShowPopup(true);
  };

  const handlePopupChoice = (choice) => {
    setEmailReceipt(choice);
    if (!choice) {
      setShowPopup(false);
      setShowConfirm(true);
    }
    // If yes, keep popup open for email input
  };

  const handleEmailSubmit = (e) => {
    e.preventDefault();
    setShowPopup(false);
    setShowConfirm(true);
  };

  const handleConfirmPayment = async () => {
    setShowConfirm(false);
    let emailSent = false;
    if (emailReceipt && emailInput) {
      try {
        const response = await fetch("http://localhost:5001/api/send-receipt", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: emailInput,
            books: selectedBooks,
            total: totalPrice
          })
        });
        const result = await response.json();
        emailSent = result.success;
      } catch (err) {
        emailSent = false;
      }
    }
    alert(`Payment successful${emailReceipt && emailInput ? (emailSent ? ` and receipt sent to ${emailInput}` : ` but failed to send receipt`) : "."}`);
    localStorage.removeItem("selectedCartIds");
    // Remove selected books from cart
    setCart(cart.filter(book => !selectedIds.includes(book.id)));
    setCleared(true);
  };

  return (
    <div style={{ padding: "24px", maxWidth: "600px", margin: "0 auto" }}>
      <h2>Checkout Summary</h2>
      {cleared ? (
        <div style={{ marginTop: "32px", fontSize: "1.2rem", color: "#888" }}>
          Checkout complete. No books selected.
        </div>
      ) : (
        <>
          <ul style={{ listStyle: "none", padding: 0 }}>
            {selectedBooks.map(book => (
              <li key={book.id} style={{ marginBottom: "16px", borderBottom: "1px solid #eee", paddingBottom: "8px" }}>
                <div style={{ fontWeight: "bold" }}>{book.title}</div>
                <div>Quantity: {book.quantity || 1}</div>
                <div>Price: ${book.price.toFixed(2)}</div>
                <div>Subtotal: ${(book.price * (book.quantity || 1)).toFixed(2)}</div>
              </li>
            ))}
          </ul>
          <div style={{ marginTop: "24px", fontSize: "1.2rem", fontWeight: "bold", color: "#1677FF" }}>
            Amount Due: ${totalPrice.toFixed(2)}
          </div>
          <button
            style={{
              marginTop: "24px",
              padding: "12px 32px",
              background: "#52C41A",
              color: "white",
              border: "none",
              borderRadius: "6px",
              fontWeight: "bold",
              fontSize: "1.1rem",
              cursor: "pointer",
              boxShadow: "0 2px 6px rgba(0,0,0,0.1)"
            }}
            onClick={handlePay}
          >
            Pay
          </button>
          {showPopup && (
            <div style={{
              position: "fixed",
              top: 0,
              left: 0,
              width: "100vw",
              height: "100vh",
              background: "rgba(0,0,0,0.3)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              zIndex: 2000
            }}>
              <div style={{
                background: "#fff",
                padding: "32px 24px",
                borderRadius: "8px",
                boxShadow: "0 2px 16px rgba(0,0,0,0.15)",
                textAlign: "center"
              }}>
                {emailReceipt === null && (
                  <>
                    <div style={{ fontSize: "1.2rem", marginBottom: "24px" }}>
                      Would you like an email receipt?
                    </div>
                    <button
                      style={{
                        margin: "0 12px",
                        padding: "10px 24px",
                        background: "#1677FF",
                        color: "white",
                        border: "none",
                        borderRadius: "6px",
                        fontWeight: "bold",
                        fontSize: "1rem",
                        cursor: "pointer"
                      }}
                      onClick={() => handlePopupChoice(true)}
                    >
                      Yes
                    </button>
                    <button
                      style={{
                        margin: "0 12px",
                        padding: "10px 24px",
                        background: "#888",
                        color: "white",
                        border: "none",
                        borderRadius: "6px",
                        fontWeight: "bold",
                        fontSize: "1rem",
                        cursor: "pointer"
                      }}
                      onClick={() => handlePopupChoice(false)}
                    >
                      No
                    </button>
                  </>
                )}
                {emailReceipt === true && (
                  <form onSubmit={handleEmailSubmit}>
                    <div style={{ fontSize: "1.2rem", marginBottom: "24px" }}>
                      Please enter your email for the receipt:
                    </div>
                    <input
                      type="email"
                      required
                      placeholder="your@email.com"
                      style={{
                        padding: "10px",
                        fontSize: "1rem",
                        borderRadius: "6px",
                        border: "1px solid #ccc",
                        marginBottom: "16px",
                        width: "80%"
                      }}
                      value={emailInput}
                      onChange={e => setEmailInput(e.target.value)}
                    />
                    <br />
                    <button
                      type="submit"
                      style={{
                        padding: "10px 24px",
                        background: "#1677FF",
                        color: "white",
                        border: "none",
                        borderRadius: "6px",
                        fontWeight: "bold",
                        fontSize: "1rem",
                        cursor: "pointer"
                      }}
                    >
                      Submit
                    </button>
                  </form>
                )}
              </div>
            </div>
          )}
          {showConfirm && (
            <div style={{
              position: "fixed",
              top: 0,
              left: 0,
              width: "100vw",
              height: "100vh",
              background: "rgba(0,0,0,0.3)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              zIndex: 2000
            }}>
              <div style={{
                background: "#fff",
                padding: "32px 24px",
                borderRadius: "8px",
                boxShadow: "0 2px 16px rgba(0,0,0,0.15)",
                textAlign: "center"
              }}>
                <div style={{ fontSize: "1.2rem", marginBottom: "24px" }}>
                  Please confirm your payment.
                </div>
                <button
                  style={{
                    padding: "10px 24px",
                    background: "#52C41A",
                    color: "white",
                    border: "none",
                    borderRadius: "6px",
                    fontWeight: "bold",
                    fontSize: "1rem",
                    cursor: "pointer"
                  }}
                  onClick={handleConfirmPayment}
                >
                  Confirm Payment
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default Checkout;
