import React, { useContext } from "react";
import { CartContext } from "../CartContext.jsx";

const sampleBooks = [
  { id: 1, title: "The Great Gatsby", author: "F. Scott Fitzgerald", category: "Classic", price: 12.99, cover: "https://covers.openlibrary.org/b/id/8226191-L.jpg" },
  { id: 2, title: "1984", author: "George Orwell", category: "Dystopian", price: 10.99, cover: "https://covers.openlibrary.org/b/id/7222246-L.jpg" },
  { id: 3, title: "To Kill a Mockingbird", author: "Harper Lee", category: "Classic", price: 11.99, cover: "https://covers.openlibrary.org/b/id/10582258-L.jpg" },
  { id: 4, title: "The Adventures of Sherlock Holmes", author: "Arthur Conan Doyle", category: "Mystery", price: 13.99, cover: "https://covers.openlibrary.org/b/id/8231856-L.jpg" },
  { id: 5, title: "Harry Potter and the Sorcerer's Stone", author: "J.K. Rowling", category: "Fantasy", price: 14.99, cover: "https://covers.openlibrary.org/b/id/7884866-L.jpg" },
  { id: 6, title: "Pride and Prejudice", author: "Jane Austen", category: "Classic", price: 9.99, cover: "https://covers.openlibrary.org/b/id/8235116-L.jpg" },
  { id: 7, title: "The Hobbit", author: "J.R.R. Tolkien", category: "Fantasy", price: 13.49, cover: "https://covers.openlibrary.org/b/id/6979861-L.jpg" },
  { id: 8, title: "The Catcher in the Rye", author: "J.D. Salinger", category: "Classic", price: 10.49, cover: "https://covers.openlibrary.org/b/id/8225261-L.jpg" },
  { id: 9, title: "Moby-Dick", author: "Herman Melville", category: "Classic", price: 12.49, cover: "https://covers.openlibrary.org/b/id/8100921-L.jpg" },
  { id: 10, title: "War and Peace", author: "Leo Tolstoy", category: "Classic", price: 15.99, cover: "https://covers.openlibrary.org/b/id/8235117-L.jpg" },
  { id: 11, title: "The Lord of the Rings", author: "J.R.R. Tolkien", category: "Fantasy", price: 16.99, cover: "https://covers.openlibrary.org/b/id/8231857-L.jpg" },
  { id: 12, title: "Brave New World", author: "Aldous Huxley", category: "Dystopian", price: 11.49, cover: "https://covers.openlibrary.org/b/id/8226192-L.jpg" },
  { id: 13, title: "Jane Eyre", author: "Charlotte Brontë", category: "Classic", price: 10.99, cover: "https://covers.openlibrary.org/b/id/8235118-L.jpg" },
  { id: 14, title: "The Odyssey", author: "Homer", category: "Classic", price: 13.99, cover: "https://covers.openlibrary.org/b/id/8235119-L.jpg" },
  { id: 15, title: "Crime and Punishment", author: "Fyodor Dostoevsky", category: "Classic", price: 12.99, cover: "https://covers.openlibrary.org/b/id/8235120-L.jpg" },
  { id: 16, title: "The Alchemist", author: "Paulo Coelho", category: "Adventure", price: 12.49, cover: "https://covers.openlibrary.org/b/id/8235121-L.jpg" },
  { id: 17, title: "Charlotte's Web", author: "E.B. White", category: "Children", price: 8.99, cover: "https://covers.openlibrary.org/b/id/8235122-L.jpg" },
  { id: 18, title: "The Lion, the Witch and the Wardrobe", author: "C.S. Lewis", category: "Fantasy", price: 11.99, cover: "https://covers.openlibrary.org/b/id/8235123-L.jpg" },
  { id: 19, title: "The Da Vinci Code", author: "Dan Brown", category: "Thriller", price: 13.99, cover: "https://covers.openlibrary.org/b/id/8235124-L.jpg" },
  { id: 20, title: "The Hunger Games", author: "Suzanne Collins", category: "Dystopian", price: 12.99, cover: "https://covers.openlibrary.org/b/id/8235125-L.jpg" },
  { id: 21, title: "The Fault in Our Stars", author: "John Green", category: "Young Adult", price: 10.99, cover: "https://covers.openlibrary.org/b/id/8235126-L.jpg" },
  { id: 22, title: "Percy Jackson & the Olympians: The Lightning Thief", author: "Rick Riordan", category: "Fantasy", price: 11.49, cover: "https://covers.openlibrary.org/b/id/8235127-L.jpg" },
  { id: 23, title: "The Girl with the Dragon Tattoo", author: "Stieg Larsson", category: "Mystery", price: 13.99, cover: "https://covers.openlibrary.org/b/id/8235128-L.jpg" },
  { id: 24, title: "Gone Girl", author: "Gillian Flynn", category: "Thriller", price: 12.99, cover: "https://covers.openlibrary.org/b/id/8235129-L.jpg" },
  { id: 25, title: "The Kite Runner", author: "Khaled Hosseini", category: "Drama", price: 11.99, cover: "https://covers.openlibrary.org/b/id/8235130-L.jpg" },
  { id: 26, title: "Twilight", author: "Stephenie Meyer", category: "Fantasy", price: 10.99, cover: "https://covers.openlibrary.org/b/id/8235131-L.jpg" },
  { id: 27, title: "The Book Thief", author: "Markus Zusak", category: "Historical", price: 12.49, cover: "https://covers.openlibrary.org/b/id/8235132-L.jpg" },
  { id: 28, title: "The Maze Runner", author: "James Dashner", category: "Dystopian", price: 11.99, cover: "https://covers.openlibrary.org/b/id/8235133-L.jpg" },
  { id: 29, title: "Divergent", author: "Veronica Roth", category: "Dystopian", price: 11.49, cover: "https://covers.openlibrary.org/b/id/8235134-L.jpg" },
  { id: 30, title: "The Secret Garden", author: "Frances Hodgson Burnett", category: "Children", price: 9.99, cover: "https://covers.openlibrary.org/b/id/8235135-L.jpg" },
  { id: 31, title: "Little Women", author: "Louisa May Alcott", category: "Classic", price: 10.99, cover: "https://covers.openlibrary.org/b/id/8235136-L.jpg" },
  { id: 32, title: "Anne of Green Gables", author: "L.M. Montgomery", category: "Classic", price: 9.99, cover: "https://covers.openlibrary.org/b/id/8235137-L.jpg" },
  { id: 33, title: "Dracula", author: "Bram Stoker", category: "Horror", price: 12.99, cover: "https://covers.openlibrary.org/b/id/8235138-L.jpg" },
  { id: 34, title: "Frankenstein", author: "Mary Shelley", category: "Horror", price: 11.99, cover: "https://covers.openlibrary.org/b/id/8235139-L.jpg" },
  { id: 35, title: "The Picture of Dorian Gray", author: "Oscar Wilde", category: "Classic", price: 10.99, cover: "https://covers.openlibrary.org/b/id/8235140-L.jpg" },
  { id: 36, title: "The Little Prince", author: "Antoine de Saint-Exupéry", category: "Children", price: 8.99, cover: "https://covers.openlibrary.org/b/id/8235141-L.jpg" },
  { id: 37, title: "The Wind in the Willows", author: "Kenneth Grahame", category: "Children", price: 9.49, cover: "https://covers.openlibrary.org/b/id/8235142-L.jpg" },
  { id: 38, title: "Matilda", author: "Roald Dahl", category: "Children", price: 8.99, cover: "https://covers.openlibrary.org/b/id/8235143-L.jpg" },
  { id: 39, title: "The Giver", author: "Lois Lowry", category: "Young Adult", price: 10.99, cover: "https://covers.openlibrary.org/b/id/8235144-L.jpg" },
  { id: 40, title: "The Color Purple", author: "Alice Walker", category: "Drama", price: 11.99, cover: "https://covers.openlibrary.org/b/id/8235145-L.jpg" },
  { id: 41, title: "The Stand", author: "Stephen King", category: "Horror", price: 13.99, cover: "https://covers.openlibrary.org/b/id/8235146-L.jpg" },
  { id: 42, title: "It", author: "Stephen King", category: "Horror", price: 14.99, cover: "https://covers.openlibrary.org/b/id/8235147-L.jpg" },
  { id: 43, title: "The Shining", author: "Stephen King", category: "Horror", price: 13.49, cover: "https://covers.openlibrary.org/b/id/8235148-L.jpg" },
  { id: 44, title: "A Tale of Two Cities", author: "Charles Dickens", category: "Classic", price: 10.99, cover: "https://covers.openlibrary.org/b/id/8235149-L.jpg" },
  { id: 45, title: "Great Expectations", author: "Charles Dickens", category: "Classic", price: 11.99, cover: "https://covers.openlibrary.org/b/id/8235150-L.jpg" },
  { id: 46, title: "Oliver Twist", author: "Charles Dickens", category: "Classic", price: 9.99, cover: "https://covers.openlibrary.org/b/id/8235151-L.jpg" },
  { id: 47, title: "The Time Machine", author: "H.G. Wells", category: "Science Fiction", price: 12.49, cover: "https://covers.openlibrary.org/b/id/8235152-L.jpg" },
  { id: 48, title: "Journey to the Center of the Earth", author: "Jules Verne", category: "Science Fiction", price: 11.99, cover: "https://covers.openlibrary.org/b/id/8235153-L.jpg" },
  { id: 49, title: "Twenty Thousand Leagues Under the Sea", author: "Jules Verne", category: "Science Fiction", price: 12.99, cover: "https://covers.openlibrary.org/b/id/8235154-L.jpg" },
  { id: 50, title: "Don Quixote", author: "Miguel de Cervantes", category: "Classic", price: 13.99, cover: "https://covers.openlibrary.org/b/id/8235155-L.jpg" }
];

const BookList = () => {
  const { cart, setCart } = useContext(CartContext);

  const handleAddToCart = (book) => {
    setCart((prevCart) => {
      const exists = prevCart.find((item) => item.id === book.id);
      if (exists) {
        return prevCart.map((item) =>
          item.id === book.id ? { ...item, quantity: (item.quantity || 1) + 1 } : item
        );
      } else {
        return [...prevCart, { ...book, quantity: 1 }];
      }
    });
  };

  return (
    <div style={{ padding: "24px" }}>
      <h2>Available Books</h2>
      <div style={{ display: "flex", gap: "24px", flexWrap: "wrap" }}>
        {sampleBooks.map((book) => (
          <div
            key={book.id}
            style={{
              border: "1px solid #eee",
              borderRadius: "8px",
              width: "200px",
              padding: "16px",
              background: "#fff",
              boxShadow: "0 2px 8px rgba(0,0,0,0.05)",
              position: "relative",
              minHeight: "320px",
              position: "relative",
              minHeight: "320px"
            }}
          >
            <img
              src={book.cover}
              alt={book.title}
              style={{ width: "100%", height: "auto", borderRadius: "4px" }}
            />
            <h3 style={{ margin: "12px 0 4px 0" }}>{book.title}</h3>
            <p style={{ margin: "0", color: "#888" }}>by {book.author}</p>
            <p style={{ margin: "8px 0", fontWeight: "bold" }}>
              ${book.price.toFixed(2)}
            </p>
            <p style={{ margin: "0", color: "#52C41A" }}>{book.category}</p>
            <div style={{ position: "absolute", right: "16px", bottom: "16px", display: "flex", alignItems: "center" }}>
              <button
                style={{
                  padding: "8px 16px",
                  background: "#007bff",
                  color: "#fff",
                  border: "none",
                  borderRadius: "4px",
                  cursor: "pointer",
                  boxShadow: "0 2px 6px rgba(0,0,0,0.1)"
                }}
                onClick={() => handleAddToCart(book)}
              >
                Add
              </button>
              {(() => {
                const cartItem = cart.find((item) => item.id === book.id);
                if (cartItem && cartItem.quantity > 0) {
                  return (
                    <span style={{
                      marginLeft: "8px",
                      background: "#52C41A",
                      color: "white",
                      borderRadius: "12px",
                      padding: "2px 10px",
                      fontSize: "1rem",
                      fontWeight: "bold"
                    }}>
                      x{cartItem.quantity}
                    </span>
                  );
                }
                return null;
              })()}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default BookList;
