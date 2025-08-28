import cors from "cors";
import express from "express";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import mongoose from "mongoose";

// loading environment from env file
dotenv.config();

//connecting to MondoDB
const mongoUrl = process.env.MONGO_URL || "mongodb://localhost/jobtree";
mongoose.connect(mongoUrl);

//user schema
const User = mongoose.model("User", {
  name: {
    type: String,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    // https://codemia.io/knowledge-hub/path/mongoose_-_validate_email_syntax
    validate: {
      validator: function (v) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
      },
      message: props => `${props.value} is not a valid email address!`
    }
  },
  password: {
    type: String,
    required: true,
  },
  accessToken: {
    type: String,
    default: () => crypto.randomBytes(128).toString("hex"),
  },
});

const Posting = mongoose.model("Posting", {
  jobTitle: {
    type: String,
    require: true,
  },
  company: {
    type: String,
    require: true,
  },
  stage: {
    type: String,
    require: true,
    enum: ["applied", "interview", "offer", "rejected"],
    default: "applied",
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  userName: {
    type: String,
    require: true,
  },
  lastStageChange: {
    type: Date,
    default: Date.now,
  }
});

// Contact schema
const Contact = mongoose.model("Contact", {
  name: {
    type: String,
    required: true,
  },
  company: {
    type: String,
    required: true,
  },
  notes: {
    type: String,
    default: "",
  },
  userName: {
    type: String,
    required: true,
  }
});

// Defines the port the app will run on. Defaults to 8080, but can be overridden
// when starting the server. Example command to overwrite PORT env variable value:
// PORT=9000 npm start
const port = process.env.PORT || 8080;
const app = express();

// Add middlewares to enable cors and json body parsing
app.use(cors());
app.use(express.json());

//endpoint for creating a user
app.post("/users", async (req, res) => {
  const userName = req.body.user;
  const email = req.body.email;
  const password = req.body.password;
  if (!userName || !email || !password) {
    res
      .status(400)
      .send({ error: "Could not create user. User, email or password missing" });
    return;
  }
  try {
    const user = new User({
      name: userName,
      password: bcrypt.hashSync(password),
      email: email,
    });
    await user.save();
    res.status(201).send(user);
  } catch (error) {
    res.status(400).send({ error: error });
  }
});

//endpoint for logging
app.post("/users/:userName", async (req, res) => {
  const userName = req.params.userName;
  const passEncrypted = req.body.password;
  if (!passEncrypted) {
    res.json({ error: "password missing in the body of request" });
  }
  const user = await User.findOne({ name: userName });

  if (user && bcrypt.compareSync(passEncrypted, user.password)) {
    //success
    res.json({ userName: user.name, accessToken: user.accessToken });
  } else {
    //failure
    res.status(401).json({ notFound: true });
  }
});

///authenticating middleware
const authenticateUser = async (req, res, next) => {
  const user = await User.findOne({ accessToken: req.header("Authorization") });
  if (user) {
    req.user = user;
    next();
  } else {
    res.status(401).json({ error: "User logged out" });
  }
};

//
// Posting section
//

// creating a posting 
app.post("/postings", authenticateUser);
app.post("/postings", async (req, res) => {
  const jobTitle = req.body.jobTitle;
  const company = req.body.company;

  if (!jobTitle || !company) {
    res.status(400).send({ error: "Could not create posting. Job title or company missing" });
    return;
  }

  const posting = new Posting({
    jobTitle: jobTitle,
    company: company,
    userName: req.user.name
  });
  await posting.save();
  res.status(201).send(posting);
});

//fetching all postings for an authenticated user   
app.get("/postings/user", authenticateUser);
app.get("/postings/user", async (req, res) => {
  const postings = await Posting.find({ userName: req.user.name });
  res.send(postings);
});

//updating a posting from an authenticated user
app.put("/postings/:id", authenticateUser);
app.put("/postings/:id", async (req, res) => {
  const postingId = req.params.id;
  const { jobTitle, company, stage } = req.body;

  const posting = await Posting.findOne({ _id: postingId, userName: req.user.name });

  if (!posting) {
    return res.status(404).send({ error: "Posting not found or user not authorized" });
  }

  posting.jobTitle = jobTitle || posting.jobTitle;
  posting.company = company || posting.company;

  // Update lastStageChange only if stage is changed
  if (stage && stage !== posting.stage) {
    posting.stage = stage;
    posting.lastStageChange = new Date();
  } else {
    posting.stage = stage || posting.stage;
  }

  await posting.save();
  res.send(posting);
});

// Get a single posting by id
app.get("/postings/:id", authenticateUser);
app.get("/postings/:id", async (req, res) => {
  const postingId = req.params.id;
  const posting = await Posting.findOne({ _id: postingId, userName: req.user.name });
  if (!posting) {
    return res.status(404).send({ error: "Posting not found or user not authorized" });
  }
  res.send(posting);
});

// Delete a posting by id
app.delete("/postings/:id", authenticateUser);
app.delete("/postings/:id", async (req, res) => {
  const postingId = req.params.id;
  const posting = await Posting.findOneAndDelete({ _id: postingId, userName: req.user.name });
  if (!posting) {
    return res.status(404).send({ error: "Posting not found or user not authorized" });
  }
  res.send({ success: true });
});

// Contacts API

// Get all contacts for authenticated user
app.get("/contacts", authenticateUser);
app.get("/contacts", async (req, res) => {
  const contacts = await Contact.find({ userName: req.user.name });
  res.send(contacts);
});

// Add a new contact
app.post("/contacts", authenticateUser);
app.post("/contacts", async (req, res) => {
  const { name, company, notes } = req.body;
  if (!name || !company) {
    return res.status(400).send({ error: "Name and company are required" });
  }
  const contact = new Contact({
    name,
    company,
    notes,
    userName: req.user.name
  });
  await contact.save();
  res.status(201).send(contact);
});

// Update a contact
app.put("/contacts/:id", authenticateUser);
app.put("/contacts/:id", async (req, res) => {
  const contactId = req.params.id;
  const { name, company, notes } = req.body;
  const contact = await Contact.findOne({ _id: contactId, userName: req.user.name });
  if (!contact) {
    return res.status(404).send({ error: "Contact not found or user not authorized" });
  }
  contact.name = name || contact.name;
  contact.company = company || contact.company;
  contact.notes = notes || contact.notes;
  await contact.save();
  res.send(contact);
});

// Delete a contact
app.delete("/contacts/:id", authenticateUser);
app.delete("/contacts/:id", async (req, res) => {
  const contactId = req.params.id;
  const contact = await Contact.findOneAndDelete({ _id: contactId, userName: req.user.name });
  if (!contact) {
    return res.status(404).send({ error: "Contact not found or user not authorized" });
  }
  res.send({ success: true });
});

// Start defining your routes here
app.get("/", (req, res) => {
  res.send("Hello Technigo!");
});

// Starting the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
