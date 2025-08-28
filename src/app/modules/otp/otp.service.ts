// general-otp.service.ts
import AppError from "../../errorHelpers/AppError";
import { sendEmail } from "../../utils/sendEmail";
import { User } from "../user/user.model";
import {
  generateOtp,
  futureDate,
  OTP_EXP_SECONDS,
} from "../../helpers/otp.helpers";

type Purpose = "verify_email" | "reset_password" | "2fa" | string;

const sendOTP = async (email: string, purpose: Purpose) => {
  const user = await User.findOne({ email });
  if (!user) throw new AppError(404, "User not found");

  if (purpose === "verify_email" && user.isVerified) {
    throw new AppError(401, "You are already verified");
  }

  const code = generateOtp(6);

  user.otpCode = code;
  user.otpExpiresAt = futureDate(OTP_EXP_SECONDS);
  user.otpPurpose = purpose;
  await user.save();

  await sendEmail({
    to: email,
    subject: "Your One-Time Code",
    templateName: "otp",
    templateData: {
      name: user.name,
      otp: code,
      expiresInMinutes: Math.floor(OTP_EXP_SECONDS / 60),
    },
  });
};

const verifyOTP = async (
  email: string,
  code: string,
  purpose: Purpose
) => {
  const user = await User.findOne({ email });
  if (!user) throw new AppError(404, "User not found");

  if (!user.otpCode || !user.otpExpiresAt) {
    throw new AppError(401, "Invalid or expired OTP");
  }

  if (user.otpPurpose !== purpose) {
    throw new AppError(401, "OTP purpose mismatch");
  }

  if (user.otpExpiresAt.getTime() < Date.now()) {
    // clear expired
    user.otpCode = null;
    user.otpExpiresAt = null;
    user.otpPurpose = null;
    await user.save();
    throw new AppError(401, "OTP expired");
  }

  if (user.otpCode !== code) {
    throw new AppError(401, "Invalid OTP");
  }

  if (user.isVerified === false && purpose === "verify_email") {
    user.isVerified = true; // mark verified on email verification
  }

  user.otpCode = null;
  user.otpExpiresAt = null;
  user.otpPurpose = null;
  await user.save();

  return user;
};

export const OTPService = { sendOTP, verifyOTP };
