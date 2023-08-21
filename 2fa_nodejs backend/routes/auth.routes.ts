import { Router } from "express";
import {
  RegisterUser,
  LoginUser,
  GenerateOTP,
  VerifyOTP,
  ValidateOTP,
  DisableOTP,
} from "../controllers/auth.controller";

const router = Router();

router.post("/register", RegisterUser); // Use "/register" instead of "/registrer"
router.post("/login", LoginUser);
router.post("/otp/generate", GenerateOTP);
router.post("/otp/verify", VerifyOTP);
router.post("/otp/validate", ValidateOTP);
router.post("/otp/disable", DisableOTP);

export default router;
