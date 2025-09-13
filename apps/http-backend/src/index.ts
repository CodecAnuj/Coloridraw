import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { JWT_SECRET } from "@repo/backend-common/config";
import { middleware } from "./middleware";
import {
  CreateUserSchema,
  SigninSchema,
  CreateRoomSchema,
} from "@repo/common/types";
import { prismaClient } from "@repo/db/client";

const app = express();
app.use(express.json());

app.post("/signup", async (req, res) => {
  // 1. validate input
  const parse = CreateUserSchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ message: "Invalid input format" });
  }

  const { username, password, name } = parse.data;

  try {
    // 2. Check if user already exists
    const existingUser = await prismaClient.user.findUnique({
      where: {
        username: username,
      },
    });
    if (existingUser) {
      return res.status(409).json({
        message: res.status(409).json({ message: "User already exists" }),
      });
    }

    // 3. Hash the password (bcrypt automatically salts)
    const hasedPassword = await bcrypt.hash(password, 10);

    // 2. Store hash in DB
    const user = await prismaClient.user.create({
      data: {
        username: username,
        password: hasedPassword,
        name: name,
      },
    });
    res.status(201).json({
      message: "User created successfully",
      userId: user.id,
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({
      message: "Internal server error",
    });
  }
});

app.post("/signin", async (req, res) => {
  // 1. validate input
  const parse = SigninSchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ message: "Invalid input format" });
  }

  const { username, password } = parse.data;

  try {
    // 2. Find user by usenamer
    const user = await prismaClient.user.findFirst({
      where: {
        username: username,
      },
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // 3. Compare plain password with hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // 4. Generate token
    const token = jwt.sign(
      {
        userId: user?.id,
      },
      JWT_SECRET,
      {
        expiresIn: "1h", // ⏳ Token expiry
      }
    );

    res.json({
      token,
    });
  } catch (err) {
    console.error("Signin error:", err);
    res.status(500).json({
      message: "Internal server error",
    });
  }
});

app.post("/room", middleware, async (req, res) => {
  const parse = CreateRoomSchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ message: "Invalid input format" });
  }

  const { slug } = parse.data;
  const userId = req.userId as string;

  try {
    const room = await prismaClient.room.create({
      data: {
        slug: slug,
        adminId: userId,
      },
    });

    res.status(201).json({
      message: "Room created successfuly",
      roomId: room.id,
      slug: room.slug,
    });
  } catch (err: any) {
    if (err.code === "P2002") {
      // Prisma unique constraint error (slug duplicate)
      return res.status(409).json({ message: "Slug already exists" });
    }
    console.error("Room creation error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.listen(3001);
