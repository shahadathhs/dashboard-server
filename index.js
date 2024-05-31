const express = require('express');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const stripe = require("stripe");
const app = express();
require('dotenv').config();
const port = process.env.PORT || 5000;

// Initialize Stripe with the secret key
const stripeInstance = stripe(process.env.STRIPE_SECRET_KEY)

//middleware
app.use(
  cors({
    origin: [
      "http://localhost:5173",
    ],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.json());

const user = process.env.DB_USER
const password = process.env.DB_PASS

const uri = `mongodb+srv://${user}:${password}@cluster0.ahaugjj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    //await client.connect();

    const database = client.db("dashboardDB");
    const usersCollection = database.collection("users");
    const paymentsCollection = database.collection('payments');
    const cartsCollection = database.collection("carts");
    
    // Middleware to verify token for private routes
    const verifyToken = async (req, res, next) => {
      // Extract the token from cookies
      const token = req.cookies?.token;
      console.log("middleware token", token);

      // If token is not available, return Unauthorized status
      if (!token) {
        return res.status(401).send({ message: "Unauthorized" });
      }

      // If token is available, verify it
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, decoded) => {
        if (error) {
          // If verification fails, return Forbidden status
          return res.status(403).send({ message: "Forbidden" });
        }
        // If verification succeeds, attach the decoded token to the request object
        req.decodedToken = decoded;
        // Proceed to the next middleware or route handler
        next();
      });
    };

    // Middleware to verify admin access for admin routes
    const verifyAdmin = async (req, res, next) => {
      // Extract the email from the decoded token
      const email = req.decodedToken.email;
      // Construct a query to find the user by email
      const query = { email: email };
      // Fetch the user from the database
      const user = await usersCollection.findOne(query);
      // Check if the user's role is "admin"
      const isAdmin = user?.role === "admin";

      // If the user is not an admin, return Forbidden status
      if (!isAdmin) {
        return res.status(403).send({ message: "Forbidden" });
      }

      // If the user is an admin, proceed to the next middleware or route handler
      next();
    };

    // Define cookie options
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    };

    // JWT-related API endpoints

    // Endpoint to create and send a JWT token
    app.post("/jwt", async (req, res) => {
      const userEmail = req.body;
      console.log("user for token", userEmail);
      // Create a token using the userEmail and a secret key
      const token = jwt.sign(userEmail, process.env.ACCESS_TOKEN_SECRET);
      // Set the token in a cookie with the specified options
      res.cookie("token", token, cookieOptions).send({ loginSuccess: true });
    });

    // Endpoint to clear the JWT token
    app.post("/logout", async (req, res) => {
      const userEmail = req.body;
      console.log("logging out", userEmail);
      // Clear the token cookie
      res.clearCookie("token", { ...cookieOptions, maxAge: 0 }).send({ logoutSuccess: true });
    });

    // users related api
    app.get("/users", verifyToken, verifyAdmin, async(req, res) => {
      try {
        // Fetch all users from the users collection
        const result = await usersCollection.find().toArray();
        // Send the result back to the client
        res.send(result);
      } catch (error) {
        // Handle any errors that occurred during the process
        console.error('Error fetching users:', error);
        // Send an error response back to the client
        res.status(500).send({ error: 'An error occurred while fetching users.' });
      }
    })

    app.get("/users/admin/:email", verifyToken, verifyAdmin, async(req, res) => {
      // Extract the email from the request parameters
      const email = req.params.email;
      try {
        // Construct a query object to find the user with the provided email
        const query = { email: email };
        // Execute the query to find the user
        const user = await usersCollection.findOne(query);
        // Initialize a variable to track if the user is an admin
        let admin = false;
        // If the user exists, check if their role is "admin"
        if (user) {
          admin = user.role === "admin";
          console.log("admin", admin); // Log the admin status for debugging purposes
        }
        // Send the admin status back to the client
        res.send({ admin });
      } catch (error) {
        // Handle any errors that occurred during the process
        console.error('Error checking admin status:', error);
        // Send an error response back to the client
        res.status(500).send({ error: 'An error occurred while checking admin status.' });
      }
    })

    app.post("/users", async(req, res) => {
      const user = req.body;
      try {
        // Construct a query object to find a user with the provided email
        const query = { email: user.email };
        // Check if a user with the provided email already exists
        const existingUser = await usersCollection.findOne(query);
        // If the user already exists, send a message indicating this
        if (existingUser) {
          return res.send({ message: "User already exists", insertedId: null });
        }
        // If the user does not exist, insert the new user into the collection
        const result = await usersCollection.insertOne(user);
        // Send the result of the insert operation back to the client
        res.send(result);
      } catch (error) {
        // Handle any errors that occurred during the process
        console.error('Error inserting user:', error);
        // Send an error response back to the client
        res.status(500).send({ error: 'An error occurred while inserting the user.' });
      }
    })

    app.delete("/users/admin/:id", verifyToken, verifyAdmin, async(req, res) => {
      // Extract the user ID from the request parameters
      const id = req.params.id;
      try {
        // Construct a query object to find the user with the provided ID
        const query = { _id: new ObjectId(id) };
        // Execute the delete operation to remove the user
        const result = await usersCollection.deleteOne(query);
        // Send the result of the delete operation back to the client
        res.send(result);
      } catch (error) {
        // Handle any errors that occurred during the process
        console.error('Error deleting user:', error);
        // Send an error response back to the client
        res.status(500).send({ error: 'An error occurred while deleting the user.' });
      }
    })

    app.patch("/users/admin/:id", verifyToken, verifyAdmin, async(req, res) => {
      // Extract the user ID from the request parameters
      const id = req.params.id;
      // Construct a query object to find the user with the provided ID
      const query = { _id: new ObjectId(id) };
      // Construct an update document to set the user's role to 'admin'
      const updateDoc = {
        $set: {
          role: 'admin'
        },
      };
      try {
        // Execute the update operation to modify the user's role
        const result = await usersCollection.updateOne(query, updateDoc);
        // Send the result of the update operation back to the client
        res.send(result);
      } catch (error) {
        // Handle any errors that occurred during the process
        console.error('Error updating user role:', error);
        // Send an error response back to the client
        res.status(500).send({ error: 'An error occurred while updating the user role.' });
      }
    })
  
    //payment related api
    app.post("/create-payment-intent", verifyToken, async (req, res) => {
      const { price } = req.body;
      const amount = parseFloat(price * 100).toFixed(2); // Amount in cents
    
      try {
        // Create a PaymentIntent with the order amount and currency
        const paymentIntent = await stripeInstance.paymentIntents.create({
          amount: amount,
          currency: "usd",
          payment_method_types: ["card", "link"],
        });
    
        res.send({
          clientSecret: paymentIntent.client_secret,
        });
        console.log('Payment SUCCESS', req.body)
      } catch (error) {
        console.error('Error creating payment intent:', error);
        res.status(500).send({ error: 'Internal Server Error' });
      }
    });

    app.post('/payments', verifyToken, async(req, res) => {
      const payment = req.body;
      console.log('paymentInfo', payment);
      try {
        // Insert the payment details into the payments collection
        const paymentResult = await paymentsCollection.insertOne(payment);
        // Construct a query to delete items from the cart based on the cartIds provided in the payment
        const query = {
          _id: { $in: payment.cartIds.map(id => new ObjectId(id))  }
        };
        // Execute the delete operation to remove the specified items from the cart
        const deleteResult = await cartsCollection.deleteMany(query);
        // Send the results of both the payment insertion and cart deletion back to the client
        res.send({ paymentResult, deleteResult })
      } catch (error) {
        // Handle any errors that occurred during the process
        console.error('Error processing payment:', error);
        // Send an error response back to the client
        res.status(500).send({ error: 'An error occurred while processing the payment.' });
      }
    })

    app.get("/payments", verifyToken, verifyAdmin, async(req, res) => {
      // Extract the email from the query parameters
      const email = req.query.email;
      // Construct a query object to find payments associated with the provided email
      const query = { email: email };
      try {
        // Execute the query to find all matching payment records and convert them to an array
        const result = await paymentsCollection.find(query).toArray();
        // Send the result back to the client
        res.send(result);
      } catch (error) {
        // Handle any errors that occurred during the process
        console.error('Error fetching payment records:', error);
        // Send an error response back to the client
        res.status(500).send({ error: 'An error occurred while fetching the payment records.' });
      }
    })

    // Send a ping to confirm a successful connection
    //await client.db("admin").command({ ping: 1 });
    // Get the database and collection on which to run the operation
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    //await client.close();
  }
}
run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('Dashboard Template Server Running!')
})

app.listen(port, () => {
  console.log(`Dashboard Template listening on port ${port}`)
})