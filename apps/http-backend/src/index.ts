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
  const ParsedData = CreateUserSchema.safeParse(req.body);
  if (!ParsedData.success) {
    res.json({
      message: "Incorrect inputs",
    });
    return;
  }

  const password = req.body.password;
  // 1. Hash the password (bcrypt automatically salts)
  const hasedPassword = await bcrypt.hash(password, 10);

  try {
    // 2. Store hash in DB
    const user = await prismaClient.user.create({
      data: {
        email: ParsedData.data?.username,
        password: hasedPassword,
        name: ParsedData.data.name,
      },
    });
    res.json({
      UserId: user.id,
    });
  } catch (e) {
    res.status(411).json({
      message: "User already exists with this username",
    });
  }
});

app.post("/signin", async (req, res) => {
  const ParsedData = SigninSchema.safeParse(req.body);
  if (!ParsedData.success) {
    res.json({
      message: "Incorrect inputs",
    });
    return;
  }

  const password = req.body
  // 1. Find user by email
  const user = await prismaClient.user.findFirst({
    where: {
      email: ParsedData.data.username,
    },
  });

  if (!user) {
    res.status(401).json({
      message: "Invalid credentials",
    });
    return;
  }

  // 2. Compare plain password with hashed password
  const isMatch = await bcrypt.compare(password, user.password)

  const token = jwt.sign(
    {
      userId: user?.id,
    },
    JWT_SECRET
  );

  res.json({
    token,
  });
});

app.post("/room", middleware, (req, res) => {
  const data = CreateRoomSchema.safeParse(req.body);
  if (!data.success) {
    res.json({
      message: "Incorrect inputs",
    });
    return;
  }

  // db call
  res.json({
    roomId: "123",
  });
});

app.listen(3001);
