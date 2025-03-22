import express from "express";
import { checkAuth, signup, login, logout, updateProfile } from "../controllers/auth.controller.js";
import {protectRoute} from "../middleware/auth.middleware.js";

const router = express.Router();

router.post("/signup", signup);

router.post("/login", login);

router.post("/logout", logout);

//Middleware to not allow every user to modify the profile unless they are authenticated.
router.put("/update-profile", protectRoute, updateProfile);

router.get("/check", protectRoute, checkAuth);


export default router;