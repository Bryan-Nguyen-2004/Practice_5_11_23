import bcrypt from "bcrypt";
import jwt from "jsonwebtoken"; // give us a way to send a user a webtoken for authorization
import User from "../models/User.js";

/* REGISTER USER */
export const register = async (req, res) => {  // async enables your program to start a potentially long-running task and still be able to be responsive to other 
                                               // events while that task runs, rather than having to wait until that task has finished
    try {
      const { // creates constants out of these parameters in the body
        firstName,
        lastName,
        email,
        password,
        picturePath,
        friends,
        location,
        occupation,
      } = req.body;
  
      const salt = await bcrypt.genSalt(); // The await operator is used to wait for a Promise and get its fulfillment value
      const passwordHash = await bcrypt.hash(password, salt);
  
      const newUser = new User({ // creates new user with parameters from request
        firstName,
        lastName,
        email,
        password: passwordHash, // uses hashed password
        picturePath,
        friends,
        location,
        occupation,
        viewedProfile: Math.floor(Math.random() * 10000),
        impressions: Math.floor(Math.random() * 10000),
      });
      const savedUser = await newUser.save(); // sends user to database
      res.status(201).json(savedUser); // send code 201 and returns json version of user
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  };
  
  /* LOGGING IN */
  export const login = async (req, res) => { 
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email: email });
      if (!user) return res.status(400).json({ msg: "User does not exist. " });
  
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(400).json({ msg: "Invalid credentials. " });

      // JSON Web Token (JWT) is an open standard (RFC 7519) for securely transmitting information between parties as JSON object.
      // The purpose of using JWT is not to hide data but to ensure the authenticity of the data. JWT is signed and encoded, not encrypted. 
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
      delete user.password; // deletes password so taht it isn't sent back to the frontend
      res.status(200).json({ token, user });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  };