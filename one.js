const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const app = express();

const User = mongoose.model("User", {});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).send("Invalid username or password");
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).send("Invalid username or password");
    }
    const payload = { userId: user._id };
    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal server error");
  }
});

app.get("/products/:minPrice", async (req, res) => {
  const minPrice = parseInt(req.params.minPrice);

  try {
    const products = await Product.find({ price: { $gt: minPrice } }).sort({
      price: -1,
    });

    res.json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
