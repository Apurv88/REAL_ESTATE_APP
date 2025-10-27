Dream Home - Full-Stack Real Estate App(Link:- https://real-estate-app-t269.vercel.app/ )

A full-stack real estate listing platform with role-based dashboards for buyers, sellers, and agents, built with Node.js, Express, MySQL, and JavaScript.

Key Features & Stack:-
->Backend: Node.js, Express.js, MySQL, JWT for auth, multer for image uploads.
->Frontend:JavaScript, Tailwind CSS .
->Authentication: Role-based (Buyer, Seller, Agent) registration and login.
->Property Management: Full CRUD for properties, including multiple image uploads.
->Dashboards: Unique UIs for each role to manage listings (Sellers/Agents) or browse (Buyers).

Real-World Workflow: For Sale->Pending->Sold status system.

Quick Start (Local Setup):-
Backend:
->Run npm install.
->Update the dbConfig in server.js with your MySQL credentials.
->Create the uploads folder: mkdir uploads.
->Run the server: node server.js. (Database and tables are created automatically).

Frontend:
->Open index.html in your browser (e.g., with the VS Code "Live Server" extension).

Test Users:
Login with these pre-seeded accounts:
Seller: seller@test.com (pw: password123)
Buyer: buyer@test.com (pw: password123)
