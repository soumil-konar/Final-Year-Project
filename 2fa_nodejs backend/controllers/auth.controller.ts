import { Request, Response, NextFunction } from "express";
import { PrismaClient, Prisma } from "@prisma/client";
import crypto from "crypto";
import OTPAuth from "otpauth";
import { encode } from "hi-base32";

const prisma = new PrismaClient();

const RegisterUser = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { name, email, password } = req.body;

    const hashedPassword = crypto
      .createHash("sha256")
      .update(password)
      .digest("hex");

    await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });

    res.status(201).json({
      status: "success",
      message: "Registered successfully, please login",
    });
  } catch (error: any) {
    handleError(res, error);
  }
};

const LoginUser = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(404).json({
        status: "fail",
        message: "No user with that email exists",
      });
    }

    res.status(200).json({
      status: "success",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        otp_enabled: user.otp_enabled,
      },
    });
  } catch (error: any) {
    handleError(res, error);
  }
};

const GenerateOTP = async (req: Request, res: Response) => {
  try {
    const { user_id } = req.body;

    const user = await prisma.user.findUnique({ where: { id: user_id } });

    if (!user) {
      return res.status(404).json({
        status: "fail",
        message: "No user with that ID exists",
      });
    }

    const base32_secret = generateRandomBase32();

    const totp = new OTPAuth.TOTP({
      issuer: user.name,
      label: "Final Year Project",
      algorithm: "SHA1",
      digits: 6,
      period: 15,
      secret: base32_secret,
    });

    const otpauth_url = totp.toString();

    await prisma.user.update({
      where: { id: user_id },
      data: {
        otp_auth_url: otpauth_url,
        otp_base32: base32_secret,
      },
    });

    res.status(200).json({
      base32: base32_secret,
      otpauth_url,
    });
  } 
  catch (error) {
    res.status(400).json({
      status: "error",
      message: "Invalid JSON data in the request body",
    });
  }
};

const VerifyOTP = async (req: Request, res: Response) => {
  try {
    const { user_id, token } = req.body;

    const user = await prisma.user.findUnique({ where: { id: user_id } });
    if (!user) {
      return res.status(404).json({
        status: "fail",
        message: "No user with that ID exists",
      });
    }

    const totp = new OTPAuth.TOTP({
      issuer: user.name,
      label: "Final Year Project",
      algorithm: "SHA1",
      digits: 6,
      period: 15,
      secret: user.otp_base32!,
    });

    const delta = totp.validate({ token });

    if (delta === null) {
      return res.status(401).json({
        status: "fail",
        message: "Invalid OTP token",
      });
    }

    const updatedUser = await prisma.user.update({
      where: { id: user_id },
      data: {
        otp_enabled: true,
        otp_verified: true,
      },
    });

    res.status(200).json({
      otp_verified: true,
      user: {
        id: updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email,
        otp_enabled: updatedUser.otp_enabled,
      },
    });
  } catch (error: any) {
    handleError(res, error);
  }
};

const ValidateOTP = async (req: Request, res: Response) => {
  try {
    const { user_id, token } = req.body;
    const user = await prisma.user.findUnique({ where: { id: user_id } });

    if (!user) {
      return res.status(404).json({
        status: "fail",
        message: "No user with that ID exists",
      });
    }

    const totp = new OTPAuth.TOTP({
      issuer: user.name,
      label: "Final Year Project",
      algorithm: "SHA1",
      digits: 6,
      period: 15,
      secret: user.otp_base32!,
    });

    const delta = totp.validate({ token, window: 1 });

    if (delta === null) {
      return res.status(401).json({
        status: "fail",
        message: "Invalid OTP token",
      });
    }

    res.status(200).json({
      otp_valid: true,
    });
  } catch (error: any) {
    handleError(res, error);
  }
};

const DisableOTP = async (req: Request, res: Response) => {
  try {
    const { user_id } = req.body;

    const user = await prisma.user.findUnique({ where: { id: user_id } });
    if (!user) {
      return res.status(404).json({
        status: "fail",
        message: "No user with that ID exists",
      });
    }

    const updatedUser = await prisma.user.update({
      where: { id: user_id },
      data: {
        otp_enabled: false,
      },
    });

    res.status(200).json({
      otp_disabled: true,
      user: {
        id: updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email,
        otp_enabled: updatedUser.otp_enabled,
      },
    });
  } catch (error: any) {
    handleError(res, error);
  }
};

const generateRandomBase32 = () => {
  const buffer = crypto.randomBytes(15);
  const base32 = encode(buffer).replace(/=/g, "").substring(0, 24);
  return base32;
};

const handleError = (res: Response, error: Error) => {
  res.status(500).json({
    status: "error",
    message: error.message,
  });
};

export {
  RegisterUser,
  LoginUser,
  GenerateOTP,
  VerifyOTP,
  ValidateOTP,
  DisableOTP,
};
