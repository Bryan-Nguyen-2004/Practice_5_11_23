import jwt from "jsonwebtoken";

export const verifyToken = async (req, res, next) => { // next param allows function to continue
  try {
    let token = req.header("Authorization"); // grabs token from Authorization header from frontend

    if (!token) {
      return res.status(403).send("Access Denied");
    }

    if (token.startsWith("Bearer ")) { // want token to start with "Bearer " (just a choice)
      token = token.slice(7, token.length).trimLeft(); // get token from left of that
    }

    const verified = jwt.verify(token, process.env.JWT_SECRET); // verifiess token against secret string
    req.user = verified;
    next();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};