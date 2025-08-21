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
    unique: true,
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

const Posting = mongoose.model("Posting ", {
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
  const password = req.body.password;
  if (!userName || !password) {
    res
      .status(400)
      .send({ error: "Could not create user. User or password missing" });
    return;
  }
  try {
    const user = new User({
      name: userName,
      password: bcrypt.hashSync(password),
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
  posting.stage = stage || posting.stage;

  await posting.save();
  res.send(posting);
});

// Start defining your routes here
app.get("/", (req, res) => {
  res.send("Hello Technigo!");
});

// Starting the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
