import express from "express";
import jwt from "jsonwebtoken";
import { JWT_SECRET } from "@repo/backend-common/config";
import { middleware } from "./middleware";
import {
  CreateUserSchema,
  SigninSchema,
  CreateRoomSchema,
} from "@repo/common/types";
import { prismaClient } from "@repo/db/client";

const app = express();

app.post("/singup", (req, res) => {
  const ParsedData = CreateUserSchema.safeParse(req.body);
  if (!ParsedData.success) {
    res.json({
      message: "Incorrect inputs",
    });
    return;
  }
  const createUser = prismaClient.user.create({
    data: {
      email: ParsedData.data.username,
      password: ParsedData.data.password,
      name: ParsedData.data.name,
    },
  })
  //db call
  res.json({
    UserId: "123",
  });
});

app.post("/singin", (req, res) => {
  const data = SigninSchema.safeParse(req.body);
  if (!data.success) {
    res.json({
      message: "Incorrect inputs",
    });
    return;
  }

  const userId = 1;
  const token = jwt.sign(
    {
      userId,
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
